//! Combine base + overlay ELFs into a runnable combined executable.
//!
//! Pure splice: no relocation work. Overlay is already fully linked at
//! disjoint addresses (see `overlay.rs` — disjoint flat region on x86,
//! the slack past base's IROM/DROM on xtensa), and its references to
//! base symbols are resolved as absolute constants through
//! `base_addresses.ld`. Combine's job is just:
//!
//!   1. Copy base.elf verbatim.
//!   2. Append each overlay PT_LOAD's payload to the end of the file.
//!   3. Rewrite the program header table to include the new PT_LOADs.
//!   4. Install **one** trampoline at base's `entry_symbol` (typically
//!      `main`), redirecting crt (or the boot path) to overlay's entry.
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
//! Class-aware (ELF32 + ELF64) so this works for both x86_64 hosted
//! (ELF64) and xtensa esp32s3 (ELF32).

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use object::{Object, ObjectSymbol, elf::PT_LOAD};

use crate::{elf_attach, metadata};

/// ELF class — 32-bit or 64-bit. Detected from byte 4 of the ELF
/// header. Determines program-header size, header field offsets, and
/// width of file/address fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 5 || &bytes[..4] != b"\x7fELF" {
            bail!("not an ELF");
        }
        match bytes[4] {
            1 => Ok(ElfClass::Elf32),
            2 => Ok(ElfClass::Elf64),
            c => bail!("unknown ELF class {c}"),
        }
    }

    fn phdr_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 56,
        }
    }

    /// Byte offsets of (e_phoff, e_phentsize, e_phnum) in the ELF
    /// header, plus how many bytes e_phoff occupies (4 vs 8).
    fn header_offsets(self) -> HeaderOffsets {
        match self {
            ElfClass::Elf32 => HeaderOffsets {
                e_phoff: 28,
                e_phoff_size: 4,
                e_phentsize: 42,
                e_phnum: 44,
            },
            ElfClass::Elf64 => HeaderOffsets {
                e_phoff: 32,
                e_phoff_size: 8,
                e_phentsize: 54,
                e_phnum: 56,
            },
        }
    }
}

struct HeaderOffsets {
    e_phoff: usize,
    e_phoff_size: usize, // 4 for ELF32, 8 for ELF64
    e_phentsize: usize,
    e_phnum: usize,
}

pub fn combine(base_path: &Path, overlay_path: &Path, output_path: &Path) -> Result<Stats> {
    let base_bytes = std::fs::read(base_path)
        .with_context(|| format!("read {}", base_path.display()))?;
    let overlay_bytes = std::fs::read(overlay_path)
        .with_context(|| format!("read {}", overlay_path.display()))?;

    let base_class = ElfClass::from_bytes(&base_bytes)?;
    if base_bytes[5] != 1 {
        bail!("{}: only little-endian ELF supported", base_path.display());
    }
    if overlay_bytes.len() < 64 || &overlay_bytes[..4] != b"\x7fELF" {
        bail!("{}: not an ELF", overlay_path.display());
    }

    // Empty overlay (ET_REL with no PHT) means the closure was empty —
    // nothing to splice, nothing to trampoline. Combined output is just
    // base verbatim.
    let ov_etype = u16::from_le_bytes(overlay_bytes[16..18].try_into().unwrap());
    let ov_class = ElfClass::from_bytes(&overlay_bytes)?;
    let ov_phnum_offset = ov_class.header_offsets().e_phnum;
    let ov_phnum = u16::from_le_bytes(
        overlay_bytes[ov_phnum_offset..ov_phnum_offset + 2]
            .try_into()
            .unwrap(),
    );
    if ov_etype == object::elf::ET_REL || ov_phnum == 0 {
        write_executable(output_path, &base_bytes)?;
        return Ok(Stats {
            trampolines: Vec::new(),
            overlay_load_size: 0,
            overlay_vaddr: 0,
            combined_size: base_bytes.len() as u64,
        });
    }
    if ov_class != base_class {
        bail!(
            "ELF class mismatch: base {:?}, overlay {:?}",
            base_class,
            ov_class
        );
    }

    // Find every overlay PT_LOAD (one on x86, two-or-more on xtensa
    // due to separate IROM and DROM mappings).
    let ov_phdrs = read_program_headers(&overlay_bytes, ov_class)?;
    let overlay_loads: Vec<Phdr> = ov_phdrs
        .iter()
        .copied()
        .filter(|p| p.p_type == PT_LOAD)
        .collect();
    if overlay_loads.is_empty() {
        bail!("{}: no PT_LOAD in overlay", overlay_path.display());
    }

    // Find the one symbol we bridge: base's manifest tells us which
    // user-level entry crt calls (always `main` on hosted x86-64; the
    // bootloader entry for xtensa).
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
    // Overlay's entry must live inside one of the overlay PT_LOADs;
    // if the link resolved entry to a base PROVIDE address it'd be
    // outside, meaning the closure didn't cascade to entry — guard.
    let overlay_entry_addr = find_text_def(&overlay_obj, entry).filter(|&a| {
        overlay_loads
            .iter()
            .any(|p| a >= p.p_vaddr && a < p.p_vaddr + p.p_memsz)
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
    // can land in overlay even without a code change but are unreachable
    // without a trampoline. Short-circuit to byte-identical base output.
    if trampolines.is_empty() {
        write_executable(output_path, &base_bytes)?;
        return Ok(Stats {
            trampolines,
            overlay_load_size: 0,
            overlay_vaddr: 0,
            combined_size: base_bytes.len() as u64,
        });
    }

    // Build output: start from base, apply trampolines, append every
    // overlay PT_LOAD, append a new PHT extending base's.
    let mut out = base_bytes.clone();

    let base_phdrs = read_program_headers(&base_bytes, base_class)?;
    let e_machine = u16::from_le_bytes(base_bytes[18..20].try_into().unwrap());
    apply_trampolines(&mut out, &base_phdrs, &trampolines, e_machine)?;

    // For each overlay LOAD: append its bytes, padded to memsz; track
    // the new file offset for the rewritten PHT entry. Each LOAD is
    // page-aligned so the kernel/bootloader can mmap cleanly.
    let mut new_loads: Vec<Phdr> = Vec::with_capacity(overlay_loads.len());
    let primary_load = overlay_loads[0]; // for Stats reporting
    for ov_load in &overlay_loads {
        align_up(&mut out, 0x1000);
        let new_offset = out.len() as u64;
        let load_data = &overlay_bytes
            [ov_load.p_offset as usize..(ov_load.p_offset + ov_load.p_filesz) as usize];
        out.extend_from_slice(load_data);
        if ov_load.p_memsz > ov_load.p_filesz {
            out.resize(out.len() + (ov_load.p_memsz - ov_load.p_filesz) as usize, 0);
        }
        new_loads.push(Phdr {
            p_type: PT_LOAD,
            p_flags: ov_load.p_flags,
            p_offset: new_offset,
            p_vaddr: ov_load.p_vaddr,
            p_paddr: ov_load.p_vaddr,
            p_filesz: ov_load.p_filesz,
            p_memsz: ov_load.p_memsz,
            p_align: 0x1000,
        });
    }

    align_up(&mut out, 8);
    let new_phoff = out.len() as u64;
    let new_phnum = base_phdrs.len() + new_loads.len();
    let pht_size = new_phnum * base_class.phdr_size();

    // ELF64 hosted (x86 musl): the kernel needs e_phoff to fall inside
    // *some* PT_LOAD for AT_PHDR to be a valid virtual address (else
    // musl SEGVs in __init_libc reading phdrs for TLS setup). Stretch
    // the last new LOAD to cover the trailing PHT.
    //
    // ELF32 xtensa: bootloader walks PHT directly from the file via
    // e_phoff, doesn't require it to be inside a LOAD. Skip the stretch
    // there to avoid declaring extra memory the bootloader would try
    // to map.
    if base_class == ElfClass::Elf64
        && let Some(last) = new_loads.last_mut()
    {
        let new_filesz = (new_phoff + pht_size as u64) - last.p_offset;
        last.p_filesz = new_filesz;
        last.p_memsz = new_filesz;
    }

    for p in base_phdrs.iter().chain(new_loads.iter()) {
        out.extend_from_slice(&p.to_le_bytes(base_class));
    }

    // Patch e_phoff + e_phnum in the ELF header.
    let ho = base_class.header_offsets();
    match ho.e_phoff_size {
        4 => out[ho.e_phoff..ho.e_phoff + 4].copy_from_slice(&(new_phoff as u32).to_le_bytes()),
        8 => out[ho.e_phoff..ho.e_phoff + 8].copy_from_slice(&new_phoff.to_le_bytes()),
        n => bail!("unexpected e_phoff_size {n}"),
    }
    out[ho.e_phnum..ho.e_phnum + 2].copy_from_slice(&(new_phnum as u16).to_le_bytes());

    write_executable(output_path, &out)?;

    let total_overlay_filesz: u64 = overlay_loads.iter().map(|p| p.p_filesz).sum();
    Ok(Stats {
        trampolines,
        overlay_load_size: total_overlay_filesz,
        overlay_vaddr: primary_load.p_vaddr,
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

/// Canonical 64-bit-wide program header. ELF32 fields are zero-extended
/// on read and truncated on write.
#[derive(Debug, Clone, Copy)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl Phdr {
    fn parse(raw: &[u8], class: ElfClass) -> Self {
        match class {
            ElfClass::Elf64 => Self {
                p_type: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
                p_flags: u32::from_le_bytes(raw[4..8].try_into().unwrap()),
                p_offset: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
                p_vaddr: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
                p_paddr: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
                p_filesz: u64::from_le_bytes(raw[32..40].try_into().unwrap()),
                p_memsz: u64::from_le_bytes(raw[40..48].try_into().unwrap()),
                p_align: u64::from_le_bytes(raw[48..56].try_into().unwrap()),
            },
            ElfClass::Elf32 => {
                // ELF32 layout: type, offset, vaddr, paddr, filesz,
                // memsz, flags, align — note flags is *after* memsz.
                let r = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap()) as u64;
                Self {
                    p_type: r(0) as u32,
                    p_offset: r(4),
                    p_vaddr: r(8),
                    p_paddr: r(12),
                    p_filesz: r(16),
                    p_memsz: r(20),
                    p_flags: r(24) as u32,
                    p_align: r(28),
                }
            }
        }
    }

    fn to_le_bytes(&self, class: ElfClass) -> Vec<u8> {
        match class {
            ElfClass::Elf64 => {
                let mut b = Vec::with_capacity(56);
                b.extend_from_slice(&self.p_type.to_le_bytes());
                b.extend_from_slice(&self.p_flags.to_le_bytes());
                b.extend_from_slice(&self.p_offset.to_le_bytes());
                b.extend_from_slice(&self.p_vaddr.to_le_bytes());
                b.extend_from_slice(&self.p_paddr.to_le_bytes());
                b.extend_from_slice(&self.p_filesz.to_le_bytes());
                b.extend_from_slice(&self.p_memsz.to_le_bytes());
                b.extend_from_slice(&self.p_align.to_le_bytes());
                b
            }
            ElfClass::Elf32 => {
                let mut b = Vec::with_capacity(32);
                b.extend_from_slice(&(self.p_type).to_le_bytes());
                b.extend_from_slice(&(self.p_offset as u32).to_le_bytes());
                b.extend_from_slice(&(self.p_vaddr as u32).to_le_bytes());
                b.extend_from_slice(&(self.p_paddr as u32).to_le_bytes());
                b.extend_from_slice(&(self.p_filesz as u32).to_le_bytes());
                b.extend_from_slice(&(self.p_memsz as u32).to_le_bytes());
                b.extend_from_slice(&(self.p_flags).to_le_bytes());
                b.extend_from_slice(&(self.p_align as u32).to_le_bytes());
                b
            }
        }
    }
}

fn read_program_headers(elf: &[u8], class: ElfClass) -> Result<Vec<Phdr>> {
    let ho = class.header_offsets();
    let e_phoff = match ho.e_phoff_size {
        4 => u32::from_le_bytes(elf[ho.e_phoff..ho.e_phoff + 4].try_into().unwrap()) as usize,
        8 => u64::from_le_bytes(elf[ho.e_phoff..ho.e_phoff + 8].try_into().unwrap()) as usize,
        n => bail!("unexpected e_phoff_size {n}"),
    };
    let e_phentsize =
        u16::from_le_bytes(elf[ho.e_phentsize..ho.e_phentsize + 2].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf[ho.e_phnum..ho.e_phnum + 2].try_into().unwrap()) as usize;
    let expected = class.phdr_size();
    if e_phentsize != expected {
        bail!("unexpected e_phentsize {e_phentsize} (wanted {expected} for {class:?})");
    }
    let end = e_phoff + e_phnum * e_phentsize;
    if end > elf.len() {
        bail!("truncated PHT");
    }
    Ok((0..e_phnum)
        .map(|i| Phdr::parse(&elf[e_phoff + i * e_phentsize..e_phoff + (i + 1) * e_phentsize], class))
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
    base_phdrs: &[Phdr],
    trampolines: &[Trampoline],
    e_machine: u16,
) -> Result<()> {
    let loads: Vec<&Phdr> = base_phdrs.iter().filter(|p| p.p_type == PT_LOAD).collect();
    let tramp_size = crate::arch::trampoline_size(e_machine)?;
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
        if file_off + tramp_size > out.len() {
            bail!(
                "trampoline {} ({} bytes) patches past EOF",
                t.name,
                tramp_size
            );
        }
        let bytes = crate::arch::trampoline(e_machine, t.base_addr, t.overlay_addr)
            .with_context(|| format!("encode trampoline for {}", t.name))?;
        out[file_off..file_off + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(())
}

fn align_up(buf: &mut Vec<u8>, align: usize) {
    let pad = (align - (buf.len() % align)) % align;
    buf.resize(buf.len() + pad, 0);
}

/// Write an ELF, ensuring the result is executable. fs::write through
/// open(O_TRUNC) creates the file with the umask-default mode (~0o644),
/// stripping the +x bit even if the file existed and was executable
/// before. The single-ELF combine flow writes over cargo's output, so
/// we have to put the bit back ourselves.
fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    let mode = perms.mode();
    let new_mode = mode | 0o111; // u+x, g+x, o+x — match cargo's default for binaries.
    if new_mode != mode {
        perms.set_mode(new_mode);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod +x {}", path.display()))?;
    }
    Ok(())
}
