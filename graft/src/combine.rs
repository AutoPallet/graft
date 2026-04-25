//! Combine base + overlay ELFs into a runnable combined executable.
//!
//! Pure splice: no relocation work. Overlay is already fully linked at a
//! disjoint address range (see `overlay.rs` — 0x1000_0000 on M0.5 x86),
//! and its references to base symbols are resolved as absolute constants
//! through `base_addresses.ld`. Combine's job is just:
//!
//!   1. Copy base.elf verbatim.
//!   2. Append overlay's PT_LOAD payload to the end of the file.
//!   3. Rewrite the program header table to include the new PT_LOAD.
//!   4. Install **one** 5-byte `jmp rel32` trampoline, at base's
//!      `entry_symbol` (typically `main`), redirecting crt (_start) to
//!      overlay's entry.
//!
//! Only the entry-point trampoline is needed. Every other base→closure
//! reloc is impossible by construction: if some base section pointed
//! into the closure, its own trans_hash would have cascaded and pulled
//! the section into the closure — so by the time we're combining,
//! closure members are only called from within the closure itself, and
//! overlay's own link already has them resolved to overlay-local
//! addresses. The sole exception is `_start → main`, because crt1.o
//! isn't an overlay scan input (ld pulls it in via `-lc` rather than as
//! an explicit `.o`), so the cascade can't reach it.
//!
//! (A better long-term design is an indirection table base reads at
//! runtime — similar to how dioxus's hot-patcher dispatches — so even
//! the entry hand-off doesn't require mutating base's bytes. Deferred.)

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use object::{Object, ObjectSymbol, elf::PT_LOAD};

use crate::{elf_attach, metadata};

pub fn combine(base_path: &Path, overlay_path: &Path, output_path: &Path) -> Result<Stats> {
    let base_bytes = std::fs::read(base_path)
        .with_context(|| format!("read {}", base_path.display()))?;
    let overlay_bytes = std::fs::read(overlay_path)
        .with_context(|| format!("read {}", overlay_path.display()))?;

    if base_bytes.len() < 64 || &base_bytes[..4] != b"\x7fELF" {
        bail!("{}: not an ELF", base_path.display());
    }
    if base_bytes[4] != 2 || base_bytes[5] != 1 {
        bail!("{}: only ELF64 little-endian supported", base_path.display());
    }
    if overlay_bytes.len() < 64 || &overlay_bytes[..4] != b"\x7fELF" {
        bail!("{}: not an ELF", overlay_path.display());
    }

    // Empty overlay (ET_REL with no PHT) means the closure was empty —
    // nothing to splice, nothing to trampoline. Combined output is just
    // base verbatim.
    let ov_etype = u16::from_le_bytes(overlay_bytes[16..18].try_into().unwrap());
    let ov_phnum = u16::from_le_bytes(overlay_bytes[56..58].try_into().unwrap());
    if ov_etype == object::elf::ET_REL || ov_phnum == 0 {
        std::fs::write(output_path, &base_bytes)
            .with_context(|| format!("write {}", output_path.display()))?;
        return Ok(Stats {
            trampolines: Vec::new(),
            overlay_load_size: 0,
            overlay_vaddr: 0,
            combined_size: base_bytes.len() as u64,
        });
    }

    // Find overlay's unique PT_LOAD via raw PHT walk.
    let ov_phdrs = read_program_headers(&overlay_bytes)?;
    let loads: Vec<&Elf64Phdr> = ov_phdrs.iter().filter(|p| p.p_type == PT_LOAD).collect();
    if loads.is_empty() {
        bail!("{}: no PT_LOAD in overlay", overlay_path.display());
    }
    if loads.len() > 1 {
        bail!(
            "{}: overlay has {} PT_LOADs; M0.5 supports exactly one",
            overlay_path.display(),
            loads.len()
        );
    }
    let ov_load = *loads[0];
    let ov_load_data = &overlay_bytes
        [ov_load.p_offset as usize..(ov_load.p_offset + ov_load.p_filesz) as usize];

    // Find the one symbol we bridge: base's manifest tells us which
    // user-level entry crt calls (always `main` on hosted x86-64).
    let manifest_bytes = elf_attach::read_section(&base_bytes, metadata::SECTION_MANIFEST)?
        .ok_or_else(|| anyhow!("{}: no {}", base_path.display(), metadata::SECTION_MANIFEST))?;
    let manifest = metadata::decode_manifest(manifest_bytes)?;
    let entry = manifest.entry_symbol.as_str();

    let base_obj = object::File::parse(&*base_bytes)
        .with_context(|| format!("parse {}", base_path.display()))?;
    let overlay_obj = object::File::parse(&*overlay_bytes)
        .with_context(|| format!("parse {}", overlay_path.display()))?;
    let base_entry_addr = find_text_def(&base_obj, entry)
        .ok_or_else(|| anyhow!("entry symbol {entry:?} not defined in base"))?;
    let overlay_entry_addr = find_text_def(&overlay_obj, entry).filter(|&a| {
        // Must live inside overlay's PT_LOAD; an ABS symbol at base's
        // address would mean overlay's link resolved `main` through our
        // PROVIDE script rather than redefining it (i.e. the closure
        // didn't cascade to main — shouldn't happen with a non-empty
        // closure, but guard anyway).
        a >= ov_load.p_vaddr && a < ov_load.p_vaddr + ov_load.p_memsz
    });
    let trampolines: Vec<Trampoline> = match overlay_entry_addr {
        Some(a) => vec![Trampoline {
            name: entry.to_string(),
            base_addr: base_entry_addr,
            overlay_addr: a,
        }],
        None => Vec::new(),
    };

    // No trampoline → base never jumps into overlay. KEEP()'d sections
    // like `.init_array` or crtbegin's `__do_init` can land in overlay
    // even without any code change (they have no symbols classify can
    // match against base's symhash), but they're unreachable without a
    // trampoline. Short-circuit to byte-identical base output — this is
    // the "no-op" scenario under the M0.5 model where `main` is the
    // single redirect point.
    if trampolines.is_empty() {
        std::fs::write(output_path, &base_bytes)
            .with_context(|| format!("write {}", output_path.display()))?;
        return Ok(Stats {
            trampolines,
            overlay_load_size: 0,
            overlay_vaddr: 0,
            combined_size: base_bytes.len() as u64,
        });
    }

    // Build output: start from base, apply trampolines, append overlay
    // payload, relocate + extend PHT.
    let mut out = base_bytes.clone();

    let base_phdrs = read_program_headers(&base_bytes)?;
    apply_trampolines(&mut out, &base_phdrs, &trampolines)?;

    align_up(&mut out, 0x1000);
    let new_load_offset = out.len() as u64;
    out.extend_from_slice(ov_load_data);
    // Zero-pad up to overlay's declared p_memsz so any .bss tail lives
    // inside the file (this lets us overlap the PHT into the same LOAD
    // without clipping overlay's memsz).
    if ov_load.p_memsz > ov_load.p_filesz {
        let pad = (ov_load.p_memsz - ov_load.p_filesz) as usize;
        out.resize(out.len() + pad, 0);
    }

    align_up(&mut out, 8);
    let new_phoff = out.len() as u64;
    let phdrs = read_program_headers(&base_bytes)?;
    let new_phnum = (phdrs.len() + 1) as u64;
    let pht_size = new_phnum * 56;
    // Extend the overlay LOAD so it covers the PHT trailing it; the
    // kernel needs e_phoff to fall inside *some* LOAD segment for AT_PHDR
    // to be a valid virtual address (else musl SEGVs in __init_libc
    // reading phdrs for TLS setup).
    let new_load_filesz = (new_phoff + pht_size) - new_load_offset;
    let new_phdr = Elf64Phdr {
        p_type: PT_LOAD,
        p_flags: ov_load.p_flags,
        p_offset: new_load_offset,
        p_vaddr: ov_load.p_vaddr,
        p_paddr: ov_load.p_vaddr,
        p_filesz: new_load_filesz,
        p_memsz: new_load_filesz,
        p_align: 0x1000,
    };

    for p in &phdrs {
        out.extend_from_slice(&p.to_le_bytes());
    }
    out.extend_from_slice(&new_phdr.to_le_bytes());

    // Patch e_phoff + e_phnum in the ELF header.
    out[32..40].copy_from_slice(&new_phoff.to_le_bytes());
    out[56..58].copy_from_slice(&(new_phnum as u16).to_le_bytes());

    std::fs::write(output_path, &out)
        .with_context(|| format!("write {}", output_path.display()))?;

    Ok(Stats {
        trampolines,
        overlay_load_size: ov_load.p_filesz,
        overlay_vaddr: ov_load.p_vaddr,
        combined_size: out.len() as u64,
    })
}

pub struct Stats {
    pub trampolines: Vec<Trampoline>,
    pub overlay_load_size: u64,
    pub overlay_vaddr: u64,
    pub combined_size: u64,
}

#[derive(Debug, Clone)]
pub struct Trampoline {
    pub name: String,
    pub base_addr: u64,
    pub overlay_addr: u64,
}

#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl Elf64Phdr {
    fn parse(raw: &[u8]) -> Self {
        Elf64Phdr {
            p_type: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
            p_flags: u32::from_le_bytes(raw[4..8].try_into().unwrap()),
            p_offset: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            p_vaddr: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
            p_paddr: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
            p_filesz: u64::from_le_bytes(raw[32..40].try_into().unwrap()),
            p_memsz: u64::from_le_bytes(raw[40..48].try_into().unwrap()),
            p_align: u64::from_le_bytes(raw[48..56].try_into().unwrap()),
        }
    }
    fn to_le_bytes(&self) -> [u8; 56] {
        let mut b = [0u8; 56];
        b[0..4].copy_from_slice(&self.p_type.to_le_bytes());
        b[4..8].copy_from_slice(&self.p_flags.to_le_bytes());
        b[8..16].copy_from_slice(&self.p_offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.p_vaddr.to_le_bytes());
        b[24..32].copy_from_slice(&self.p_paddr.to_le_bytes());
        b[32..40].copy_from_slice(&self.p_filesz.to_le_bytes());
        b[40..48].copy_from_slice(&self.p_memsz.to_le_bytes());
        b[48..56].copy_from_slice(&self.p_align.to_le_bytes());
        b
    }
}

fn read_program_headers(elf: &[u8]) -> Result<Vec<Elf64Phdr>> {
    let e_phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;
    if e_phentsize != 56 {
        bail!("unexpected e_phentsize {e_phentsize} (wanted 56 for ELF64)");
    }
    let end = e_phoff + e_phnum * e_phentsize;
    if end > elf.len() {
        bail!("truncated PHT");
    }
    Ok((0..e_phnum)
        .map(|i| Elf64Phdr::parse(&elf[e_phoff + i * e_phentsize..e_phoff + (i + 1) * e_phentsize]))
        .collect())
}

fn find_text_def(elf: &object::File<'_>, name: &str) -> Option<u64> {
    elf.symbols().find_map(|s| {
        if !s.is_definition() || !matches!(s.kind(), object::SymbolKind::Text) {
            return None;
        }
        if s.name().ok()? != name {
            return None;
        }
        Some(s.address())
    })
}

fn apply_trampolines(
    out: &mut [u8],
    base_phdrs: &[Elf64Phdr],
    trampolines: &[Trampoline],
) -> Result<()> {
    let loads: Vec<&Elf64Phdr> = base_phdrs.iter().filter(|p| p.p_type == PT_LOAD).collect();
    for t in trampolines {
        let seg = loads
            .iter()
            .find(|p| t.base_addr >= p.p_vaddr && t.base_addr < p.p_vaddr + p.p_filesz)
            .ok_or_else(|| {
                anyhow!(
                    "trampoline target {:#x} ({}) not inside any base PT_LOAD",
                    t.base_addr,
                    t.name
                )
            })?;
        let file_off = (seg.p_offset + (t.base_addr - seg.p_vaddr)) as usize;
        if file_off + 5 > out.len() {
            bail!("trampoline {} patches past EOF", t.name);
        }
        // `jmp rel32`: 0xe9 + (target - source - 5) as i32 LE.
        let rel = (t.overlay_addr as i64) - (t.base_addr as i64 + 5);
        if !(i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
            bail!("trampoline {} exceeds rel32 range: {:+#x}", t.name, rel);
        }
        out[file_off] = 0xe9;
        out[file_off + 1..file_off + 5].copy_from_slice(&(rel as i32).to_le_bytes());
    }
    Ok(())
}

fn align_up(buf: &mut Vec<u8>, align: usize) {
    let pad = (align - (buf.len() % align)) % align;
    buf.resize(buf.len() + pad, 0);
}
