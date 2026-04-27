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
use object::{
    Object, ObjectSection, ObjectSymbol, SectionFlags,
    elf::{PT_LOAD, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_PROGBITS},
};

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

    let e_machine = u16::from_le_bytes(base_bytes[18..20].try_into().unwrap());
    let mode = crate::slack::Mode::resolve(e_machine)?;
    if mode == crate::slack::Mode::Splice {
        return combine_splice(
            base_path,
            &base_bytes,
            overlay_path,
            &overlay_bytes,
            base_class,
            output_path,
        );
    }

    // Find every overlay PT_LOAD. linkall.x emits dummy placeholder
    // LOADs (`.rwdata_dummy`, `.vectors`) that overlap base's RAM at
    // identical vaddrs and carry no overlay-specific data. esp-hal also
    // page-aligns DROM/IROM PT_LOADs DOWN to a 4KB boundary, so an
    // overlay's `.rodata` at 0x3c0019ac sits in a LOAD with
    // p_vaddr=0x3c001000 — overlapping base's DROM by ~6 KB even though
    // the actual content is past it. Wholesale-dropping such LOADs
    // would lose overlay's literal pool. So we *trim* each LOAD to its
    // non-overlapping subrange instead: keep only the bytes whose
    // vaddrs are strictly past every base PT_LOAD.
    let base_phdrs_for_filter = read_program_headers(&base_bytes, base_class)?;
    let base_loads: Vec<Phdr> = base_phdrs_for_filter
        .iter()
        .copied()
        .filter(|p| p.p_type == PT_LOAD)
        .collect();
    let ov_phdrs = read_program_headers(&overlay_bytes, ov_class)?;
    let mut overlay_loads: Vec<Phdr> = Vec::new();
    for ov in ov_phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        if ov.p_filesz == 0 {
            continue;
        }
        // Highest base end-vaddr that the overlay LOAD's start lands
        // before. If we're entirely past every base LOAD, no trim.
        let mut min_keep_vaddr = ov.p_vaddr;
        for b in &base_loads {
            let b_end = b.p_vaddr + b.p_memsz;
            if ov.p_vaddr < b_end && ov.p_vaddr + ov.p_memsz > b.p_vaddr {
                // Overlap. The non-overlapping tail starts at b_end.
                if b_end > min_keep_vaddr {
                    min_keep_vaddr = b_end;
                }
            }
        }
        if min_keep_vaddr >= ov.p_vaddr + ov.p_memsz {
            // Entirely overlapped — nothing to keep.
            continue;
        }
        let trim = min_keep_vaddr - ov.p_vaddr;
        overlay_loads.push(Phdr {
            p_type: PT_LOAD,
            p_flags: ov.p_flags,
            p_offset: ov.p_offset + trim,
            p_vaddr: ov.p_vaddr + trim,
            p_paddr: ov.p_paddr + trim,
            p_filesz: ov.p_filesz.saturating_sub(trim),
            p_memsz: ov.p_memsz - trim,
            p_align: ov.p_align,
        });
    }
    // Empty overlay_loads is OK if the overlay closure is genuinely
    // empty (no main redirect either) — handled by the trampoline
    // short-circuit below. Bail only if we have trampolines but no
    // payload, which would mean we'd jump into nothing.

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

    if !trampolines.is_empty() && overlay_loads.is_empty() {
        bail!(
            "trampolines reference overlay but no overlay-specific \
             PT_LOAD survived overlap trim — overlay layout broken"
        );
    }

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
    if let Some(last) = new_loads.last_mut() {
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

    // Add section headers for each overlay LOAD so downstream tools
    // (e.g., espflash, which builds image segments by walking the
    // section table rather than the PHT) actually see the overlay
    // bytes. Without this, overlay's slack PT_LOADs are present in the
    // file but invisible to espflash save-image.
    add_overlay_section_headers(&mut out, &new_loads, base_class)?;

    write_executable(output_path, &out)?;

    let total_overlay_filesz: u64 = overlay_loads.iter().map(|p| p.p_filesz).sum();
    Ok(Stats {
        trampolines,
        overlay_load_size: total_overlay_filesz,
        overlay_vaddr: primary_load.p_vaddr,
        combined_size: out.len() as u64,
    })
}

/// Xtensa splice path (M1.k): overlay's `.text` and `.rodata` are linked
/// into base's slack regions (`GRAFT_TEXT_SLACK`, `GRAFT_RODATA_SLACK`),
/// so they live *inside* base's existing IROM/DROM PT_LOADs. Combine
/// just splices the overlay section bytes over the slack-filling 0xFFs
/// in the base ELF, then patches the entry trampoline. No new PT_LOADs,
/// no PHT rewrite, no SHT extension — espflash sees a single IROM and
/// single DROM segment exactly as it did for plain base.
fn combine_splice(
    base_path: &Path,
    base_bytes: &[u8],
    overlay_path: &Path,
    overlay_bytes: &[u8],
    class: ElfClass,
    output_path: &Path,
) -> Result<Stats> {
    let base_phdrs = read_program_headers(base_bytes, class)?;
    let base_loads: Vec<Phdr> = base_phdrs
        .iter()
        .copied()
        .filter(|p| p.p_type == PT_LOAD && p.p_filesz > 0)
        .collect();

    let mut out = base_bytes.to_vec();

    let overlay_obj = object::File::parse(overlay_bytes)
        .with_context(|| format!("parse {}", overlay_path.display()))?;
    let base_obj_for_slack = object::File::parse(base_bytes)
        .with_context(|| format!("parse {}", base_path.display()))?;
    let slack_regions = read_slack_regions(&base_obj_for_slack)?;

    let mut total_spliced: u64 = 0;
    let mut overlay_vaddr_first: u64 = 0;

    for sec in overlay_obj.sections() {
        let SectionFlags::Elf { sh_flags } = sec.flags() else { continue };
        if sh_flags & u64::from(SHF_ALLOC) == 0 {
            continue;
        }
        // NOBITS (e.g. .bss) has no file_range; skip — base's
        // corresponding region won't have content to overwrite.
        let Some((sec_off, sec_size)) = sec.file_range() else { continue };
        if sec_size == 0 {
            continue;
        }
        let v_start = sec.address();
        let v_end = v_start + sec_size;
        let sec_name = sec.name().unwrap_or("?");

        // Splice mode requires every overlay section to land inside a
        // declared slack region. Anything else risks silently
        // overwriting live base content (real `.data`, real `.text`,
        // base's stack/heap region, etc.). Clobbering base RW with
        // overlay `.data` was the M1.n surprise — the symptom is
        // silent: overlay's bytes go into whatever base section
        // happens to share the vaddr. Guard rather than warn.
        let in_slack = slack_regions
            .iter()
            .any(|r| v_start >= r.start && v_end <= r.start + r.len);
        if !in_slack {
            let in_base_load = base_loads
                .iter()
                .any(|p| v_start < p.p_vaddr + p.p_filesz && v_end > p.p_vaddr);
            let detail = if in_base_load {
                "would overwrite live base content — overlay was linked at \
                 a vaddr inside a non-slack base PT_LOAD"
            } else {
                "vaddr is outside every base PT_LOAD — splice mode requires \
                 overlay sections to land in a declared slack region"
            };
            bail!(
                "overlay section {sec_name:?} at {v_start:#x}+{sec_size:#x}: \
                 {detail}. Slack regions: {slack_regions:?}"
            );
        }

        let load = base_loads
            .iter()
            .find(|p| v_start >= p.p_vaddr && v_end <= p.p_vaddr + p.p_filesz)
            .ok_or_else(|| {
                anyhow!(
                    "overlay section {sec_name:?} at {v_start:#x}+{sec_size:#x} \
                     is in slack vaddr range but no covering base PT_LOAD \
                     (slack symbol claimed an address outside base's segments?)"
                )
            })?;
        let base_off = (load.p_offset + (v_start - load.p_vaddr)) as usize;
        let src = &overlay_bytes[sec_off as usize..(sec_off + sec_size) as usize];
        out[base_off..base_off + sec_size as usize].copy_from_slice(src);
        if overlay_vaddr_first == 0 {
            overlay_vaddr_first = v_start;
        }
        total_spliced += sec_size;
    }

    // Trampoline on entry symbol — same as the appendpath, just on the
    // splice-modified buffer.
    let manifest_bytes = elf_attach::read_section(base_bytes, metadata::SECTION_MANIFEST)?
        .ok_or_else(|| anyhow!("{}: no {}", base_path.display(), metadata::SECTION_MANIFEST))?;
    let manifest = metadata::decode_manifest(manifest_bytes)?;
    let entry = manifest.entry_symbol.as_str();

    let base_entry_addr = find_text_def(&base_obj_for_slack, entry)
        .ok_or_else(|| anyhow!("entry symbol {entry:?} not defined in base"))?;
    let overlay_entry_addr = find_text_def(&overlay_obj, entry);
    let trampolines: Vec<Trampoline> = match overlay_entry_addr {
        Some(a) => vec![Trampoline {
            name: entry.to_string(),
            base_addr: base_entry_addr,
            overlay_addr: a,
        }],
        None => Vec::new(),
    };

    if trampolines.is_empty() && total_spliced == 0 {
        // Nothing changed; emit base verbatim.
        write_executable(output_path, base_bytes)?;
        return Ok(Stats {
            trampolines,
            overlay_load_size: 0,
            overlay_vaddr: 0,
            combined_size: base_bytes.len() as u64,
        });
    }

    if !trampolines.is_empty() {
        let e_machine = u16::from_le_bytes(base_bytes[18..20].try_into().unwrap());
        apply_trampolines(&mut out, &base_phdrs, &trampolines, e_machine)?;
    }

    write_executable(output_path, &out)?;

    Ok(Stats {
        trampolines,
        overlay_load_size: total_spliced,
        overlay_vaddr: overlay_vaddr_first,
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

/// A vaddr range in base.elf that splice-mode overlay sections are
/// allowed to land in. Read from `GRAFT_TEXT_SLACK` / `GRAFT_RODATA_SLACK`
/// symbols emitted by the synthetic slack `.o`.
#[derive(Clone, Copy)]
struct SlackRegion {
    name: &'static str,
    start: u64,
    len: u64,
}

impl std::fmt::Debug for SlackRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}@{:#x}+{:#x}",
            self.name, self.start, self.len
        )
    }
}

fn read_slack_regions(base: &object::File) -> Result<Vec<SlackRegion>> {
    use object::ObjectSymbol;
    let mut text: Option<(u64, u64)> = None;
    let mut rodata: Option<(u64, u64)> = None;
    for sym in base.symbols() {
        let Ok(name) = sym.name() else { continue };
        match name {
            crate::slack::TEXT_SYMBOL => text = Some((sym.address(), sym.size())),
            crate::slack::RODATA_SYMBOL => rodata = Some((sym.address(), sym.size())),
            _ => {}
        }
    }
    let mut regions = Vec::new();
    if let Some((s, l)) = text {
        regions.push(SlackRegion { name: "text", start: s, len: l });
    }
    if let Some((s, l)) = rodata {
        regions.push(SlackRegion { name: "rodata", start: s, len: l });
    }
    if regions.is_empty() {
        bail!(
            "base ELF has neither GRAFT_TEXT_SLACK nor GRAFT_RODATA_SLACK — \
             splice mode requires at least one slack region"
        );
    }
    Ok(regions)
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
    let prologue_size = crate::arch::trampoline_prologue_size(e_machine)?;
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
        // For arches that need to preserve a prologue (xtensa: the
        // windowed-ABI `entry` instruction), grab those bytes BEFORE
        // we overwrite. They live at the patch site in the (still
        // unmodified) `out` buffer.
        let prologue = out[file_off..file_off + prologue_size].to_vec();
        let bytes = crate::arch::trampoline(e_machine, t.base_addr, t.overlay_addr, &prologue)
            .with_context(|| format!("encode trampoline for {}", t.name))?;
        out[file_off..file_off + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(())
}

fn align_up(buf: &mut Vec<u8>, align: usize) {
    let pad = (align - (buf.len() % align)) % align;
    buf.resize(buf.len() + pad, 0);
}


/// Append SHT_PROGBITS section headers for each overlay PT_LOAD, plus
/// names for them in `.shstrtab`, so tools that walk the section table
/// (espflash save-image specifically) see overlay bytes.
///
/// Layout: build a fresh SHT (base's entries + one per overlay LOAD)
/// after the existing data, write a new shstrtab after that, and patch
/// e_shoff/e_shnum + the shstrtab section's sh_offset/sh_size.
fn add_overlay_section_headers(
    out: &mut Vec<u8>,
    new_loads: &[Phdr],
    class: ElfClass,
) -> Result<()> {
    if new_loads.is_empty() {
        return Ok(());
    }

    // ELF header offsets for SHT pointers — different per class.
    let (shoff_o, shoff_sz, shentsize_o, shnum_o, shstrndx_o) = match class {
        ElfClass::Elf32 => (32usize, 4usize, 46usize, 48usize, 50usize),
        ElfClass::Elf64 => (40, 8, 58, 60, 62),
    };
    let shdr_size = match class {
        ElfClass::Elf32 => 40usize,
        ElfClass::Elf64 => 64,
    };
    // Field offsets within an shdr (sh_offset/sh_size differ per class).
    let (sh_offset_field, sh_size_field, sh_field_width) = match class {
        ElfClass::Elf32 => (16usize, 20usize, 4usize),
        ElfClass::Elf64 => (24, 32, 8),
    };

    // Read existing SHT pointers from the (already-written) ELF header.
    let e_shoff = match shoff_sz {
        4 => u32::from_le_bytes(out[shoff_o..shoff_o + 4].try_into().unwrap()) as usize,
        8 => u64::from_le_bytes(out[shoff_o..shoff_o + 8].try_into().unwrap()) as usize,
        n => bail!("bad shoff_sz {n}"),
    };
    let e_shentsize =
        u16::from_le_bytes(out[shentsize_o..shentsize_o + 2].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(out[shnum_o..shnum_o + 2].try_into().unwrap()) as usize;
    let e_shstrndx =
        u16::from_le_bytes(out[shstrndx_o..shstrndx_o + 2].try_into().unwrap()) as usize;
    if e_shentsize != shdr_size {
        bail!("e_shentsize {e_shentsize} != expected {shdr_size}");
    }
    if e_shoff + e_shnum * e_shentsize > out.len() {
        bail!("truncated existing SHT");
    }
    if e_shstrndx >= e_shnum {
        bail!("e_shstrndx out of range");
    }

    // Pull the existing .shstrtab content out so we can append our
    // section names.
    let shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize;
    let read_field_at = |buf: &[u8], off: usize, w: usize| -> Result<usize> {
        Ok(match w {
            4 => u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize,
            8 => u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize,
            n => bail!("bad field width {n}"),
        })
    };
    let old_shstrtab_off = read_field_at(out, shstrtab_hdr + sh_offset_field, sh_field_width)?;
    let old_shstrtab_size = read_field_at(out, shstrtab_hdr + sh_size_field, sh_field_width)?;
    if old_shstrtab_off + old_shstrtab_size > out.len() {
        bail!("existing .shstrtab out of bounds");
    }
    let mut new_shstrtab = out[old_shstrtab_off..old_shstrtab_off + old_shstrtab_size].to_vec();

    // Allocate names; record (name_offset, sh_flags) per overlay LOAD.
    let mut new_section_meta: Vec<(u32, u64)> = Vec::with_capacity(new_loads.len());
    for (i, load) in new_loads.iter().enumerate() {
        let name = format!(".graft.overlay.{i}");
        let name_off = new_shstrtab.len() as u32;
        new_shstrtab.extend_from_slice(name.as_bytes());
        new_shstrtab.push(0);
        // Translate p_flags (PF_R=4, PF_W=2, PF_X=1) to sh_flags
        // (SHF_ALLOC=2, SHF_WRITE=1, SHF_EXECINSTR=4). PF_R is implicit
        // for any allocated section.
        let mut sh_flags = u64::from(SHF_ALLOC);
        if load.p_flags & 0x2 != 0 {
            sh_flags |= u64::from(SHF_WRITE);
        }
        if load.p_flags & 0x1 != 0 {
            sh_flags |= u64::from(SHF_EXECINSTR);
        }
        new_section_meta.push((name_off, sh_flags));
    }

    // Lift the existing SHT into a working buffer (we'll patch the
    // shstrtab entry's sh_offset/sh_size after we know where the new
    // shstrtab lands).
    let old_sht_end = e_shoff + e_shnum * e_shentsize;
    let mut new_sht = out[e_shoff..old_sht_end].to_vec();

    // Append shdrs for overlay LOADs.
    for (i, load) in new_loads.iter().enumerate() {
        let (name_off, sh_flags) = new_section_meta[i];
        let entry = build_alloc_shdr(class, name_off, load.p_offset, load.p_filesz, load.p_vaddr, sh_flags);
        new_sht.extend_from_slice(&entry);
    }

    // Place new shstrtab + new SHT at end of file. shstrtab first
    // (smaller, doesn't need much alignment), then SHT.
    align_up(out, 1);
    let new_shstrtab_off = out.len();
    out.extend_from_slice(&new_shstrtab);

    // Patch the (in-buffer) shstrtab shdr entry to point at the new
    // location.
    let shstrtab_in_new = e_shstrndx * e_shentsize;
    write_field_at(
        &mut new_sht,
        shstrtab_in_new + sh_offset_field,
        sh_field_width,
        new_shstrtab_off as u64,
    );
    write_field_at(
        &mut new_sht,
        shstrtab_in_new + sh_size_field,
        sh_field_width,
        new_shstrtab.len() as u64,
    );

    align_up(out, 8);
    let new_shoff = out.len();
    out.extend_from_slice(&new_sht);

    let new_shnum = e_shnum + new_loads.len();
    match shoff_sz {
        4 => out[shoff_o..shoff_o + 4].copy_from_slice(&(new_shoff as u32).to_le_bytes()),
        8 => out[shoff_o..shoff_o + 8].copy_from_slice(&(new_shoff as u64).to_le_bytes()),
        _ => unreachable!(),
    }
    out[shnum_o..shnum_o + 2].copy_from_slice(&(new_shnum as u16).to_le_bytes());

    Ok(())
}

fn write_field_at(buf: &mut [u8], off: usize, width: usize, value: u64) {
    match width {
        4 => buf[off..off + 4].copy_from_slice(&(value as u32).to_le_bytes()),
        8 => buf[off..off + 8].copy_from_slice(&value.to_le_bytes()),
        _ => unreachable!(),
    }
}

/// Build one SHT_PROGBITS shdr for a section that already lives in the
/// file at `sh_offset`, mapped to `sh_addr` with `sh_flags`.
fn build_alloc_shdr(
    class: ElfClass,
    sh_name: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_addr: u64,
    sh_flags: u64,
) -> Vec<u8> {
    match class {
        ElfClass::Elf32 => {
            let mut e = vec![0u8; 40];
            e[0..4].copy_from_slice(&sh_name.to_le_bytes());
            e[4..8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
            e[8..12].copy_from_slice(&(sh_flags as u32).to_le_bytes());
            e[12..16].copy_from_slice(&(sh_addr as u32).to_le_bytes());
            e[16..20].copy_from_slice(&(sh_offset as u32).to_le_bytes());
            e[20..24].copy_from_slice(&(sh_size as u32).to_le_bytes());
            // sh_link, sh_info = 0
            e[32..36].copy_from_slice(&4u32.to_le_bytes()); // sh_addralign
            // sh_entsize = 0
            e
        }
        ElfClass::Elf64 => {
            let mut e = vec![0u8; 64];
            e[0..4].copy_from_slice(&sh_name.to_le_bytes());
            e[4..8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
            e[8..16].copy_from_slice(&sh_flags.to_le_bytes());
            e[16..24].copy_from_slice(&sh_addr.to_le_bytes());
            e[24..32].copy_from_slice(&sh_offset.to_le_bytes());
            e[32..40].copy_from_slice(&sh_size.to_le_bytes());
            e[48..56].copy_from_slice(&4u64.to_le_bytes()); // sh_addralign
            e
        }
    }
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
