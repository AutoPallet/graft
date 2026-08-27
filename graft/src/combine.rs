//! Combine base + overlay ELFs into a runnable combined executable.
//!
//! Pure splice: no relocation work. Overlay is already fully linked into
//! base's reserved slack regions (see `overlay.rs` and `slack.rs`), and
//! its references to base symbols are resolved as absolute constants at
//! prune time. Combine's job is just:
//!
//!   1. Copy base.elf verbatim.
//!   2. Byte-splice each overlay section over the slack-filling 0xFFs at
//!      its file offset inside base's existing segments. (RAM-resident
//!      segments that legitimately fall past base — e.g. xtensa
//!      `.rwtext` copied flash→IRAM at boot — are appended as fresh
//!      PT_LOADs by `append_pt_loads`; everything else splices in place.)
//!   3. Install **one** trampoline at base's `entry_symbol` (typically
//!      `main`), redirecting crt (or the boot path) to overlay's entry.
//!
//! The output ELF keeps base's exact shape and (for the common
//! splice-only case) its exact size — only the slack bytes and the one
//! trampoline differ, which is what makes partial reflashing cheap.
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
    elf::{
        PT_GNU_EH_FRAME, PT_LOAD, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_ABS, SHN_LORESERVE,
        SHN_UNDEF, SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, STT_FILE, STT_SECTION, STT_TLS,
    },
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

    // Splice is the only overlay mode. Overlay's sections were linked
    // into base's reserved slack regions, so combine byte-splices them
    // in place (RAM-resident segments that legitimately fall past base,
    // e.g. xtensa `.rwtext`, are appended by `combine_splice`'s pass 2).
    combine_splice(
        base_path,
        &base_bytes,
        overlay_path,
        &overlay_bytes,
        base_class,
        output_path,
    )
}

/// The splice path (all targets). Overlay's `.text` / `.rodata` are
/// linked into base's slack regions (`GRAFT_TEXT_SLACK`,
/// `GRAFT_RODATA_SLACK`, `GRAFT_DATA_SLACK`), so they live *inside*
/// base's existing PT_LOADs. Combine splices the overlay section bytes
/// over the slack-filling 0xFFs in the base ELF, then patches the entry
/// trampoline. For the common case there are no new PT_LOADs, no PHT
/// rewrite, no SHT extension — the output is base's exact shape and
/// size. RAM-resident overlay segments that legitimately fall past base
/// (e.g. xtensa `.rwtext`) are the one exception: they're appended via
/// `append_pt_loads`. Any overlay section that would land on *live* base
/// content (outside slack, inside a base PT_LOAD) is a hard error, not a
/// silent clobber.
fn combine_splice(
    base_path: &Path,
    base_bytes: &[u8],
    overlay_path: &Path,
    overlay_bytes: &[u8],
    class: ElfClass,
    output_path: &Path,
) -> Result<Stats> {
    let mut base_phdrs = read_program_headers(base_bytes, class)?;
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
    let slack_regions = read_slack_regions(&base_obj_for_slack, base_bytes)?;

    let mut total_spliced: u64 = 0;
    let mut overlay_vaddr_first: u64 = 0;

    // Pass 1: per-section splice for SHF_ALLOC sections that land in a
    // declared slack region. Sections outside slack are *not* errors
    // here — they're handled by the append pass below. Sections that
    // overlap a non-slack base PT_LOAD *are* errors (silent clobber).
    for sec in overlay_obj.sections() {
        let SectionFlags::Elf { sh_flags } = sec.flags() else { continue };
        if sh_flags & u64::from(SHF_ALLOC) == 0 {
            continue;
        }
        let Some((sec_off, sec_size)) = sec.file_range() else { continue };
        if sec_size == 0 {
            continue;
        }
        let v_start = sec.address();
        let v_end = v_start + sec_size;
        let sec_name = sec.name().unwrap_or("?");
        // Base-map sections are address-space declarations for the
        // overlay link (anchor definitions over base's own content) —
        // never content to splice. The NOBITS ones are skipped by the
        // file_range check already; the PROGBITS TLS map (zero-filled
        // stand-in for base's .tdata span, needed because PROGBITS
        // can't follow NOBITS inside PT_TLS) must be skipped by name.
        if sec_name.starts_with(".graft.map.") {
            continue;
        }

        let in_slack = slack_regions
            .iter()
            .any(|r| v_start >= r.start && v_end <= r.start + r.len);
        if !in_slack {
            let in_base_load = base_loads
                .iter()
                .any(|p| v_start < p.p_vaddr + p.p_filesz && v_end > p.p_vaddr);
            if in_base_load {
                bail!(
                    "overlay section {sec_name:?} at {v_start:#x}+{sec_size:#x}: \
                     would overwrite live base content — overlay was linked at \
                     a vaddr inside a non-slack base PT_LOAD. Slack regions: \
                     {slack_regions:?}"
                );
            }
            // Outside slack and outside every base PT_LOAD — handled
            // by the append pass.
            continue;
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

    // Pass 2: collect overlay PT_LOADs whose sections aren't already
    // handled by the splice loop above and which lie entirely outside
    // base's PT_LOADs. A LOAD is slack-bound if any of its sections
    // falls in a slack region — those bytes were already spliced
    // section-by-section. The LOAD's leading page-alignment padding
    // (zeros between p_vaddr and the first section's vaddr) is *not*
    // appended either; splicing those zeros into base would corrupt
    // bytes outside slack.
    let ov_phdrs = read_program_headers(overlay_bytes, class)?;
    let mut append_loads: Vec<Phdr> = Vec::new();
    for ov in ov_phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.p_filesz > 0) {
        let load_v_start = ov.p_vaddr;
        let load_v_end = ov.p_vaddr + ov.p_memsz;
        let mut any_slack = false;
        let mut any_outside_base = false;
        let mut any_in_base = false;
        // Track the lowest PROGBITS section vaddr in this LOAD so we
        // can trim leading NOBITS (e.g. graft's IRAM blocker, which
        // shares the LOAD with the actual `.iram0.text` content). The
        // blocker reserves memsz inside iram0_0_seg but writes no
        // flash bytes; if we appended at the LOAD's full vaddr range
        // we'd overlap base's IRAM PT_LOAD without need.
        let mut first_progbits_vaddr: Option<u64> = None;
        for sec in overlay_obj.sections() {
            let SectionFlags::Elf { sh_flags } = sec.flags() else { continue };
            if sh_flags & u64::from(SHF_ALLOC) == 0 {
                continue;
            }
            if sec.size() == 0 {
                continue;
            }
            // NOBITS sections (e.g. graft's IRAM blocker, .bss) carry
            // no flash content — they only consume memsz at boot.
            // They can't clobber base because no bytes get written.
            // Skip them when classifying the enclosing PT_LOAD.
            if sec.file_range().is_none() {
                continue;
            }
            // Base-map sections are never content (see the splice pass).
            if sec.name().unwrap_or("").starts_with(".graft.map.") {
                continue;
            }
            let s = sec.address();
            let e = s + sec.size();
            if s < load_v_start || e > load_v_end {
                continue;
            }
            first_progbits_vaddr = Some(first_progbits_vaddr.map_or(s, |v| v.min(s)));
            let in_slack = slack_regions
                .iter()
                .any(|r| s >= r.start && e <= r.start + r.len);
            if in_slack {
                any_slack = true;
                continue;
            }
            let in_base = base_loads
                .iter()
                .any(|p| s < p.p_vaddr + p.p_memsz && e > p.p_vaddr);
            if in_base {
                any_in_base = true;
            } else {
                any_outside_base = true;
            }
        }
        if any_slack {
            // The splice pass consumed the slack-resident sections —
            // but only those. A LOAD that ALSO carries past-base
            // content would silently lose it here (the append pass
            // never sees this LOAD), so refuse the mix outright.
            // (Slack + non-slack-in-base is already a per-section
            // hard error in the splice pass.)
            if any_outside_base {
                bail!(
                    "overlay PT_LOAD at {load_v_start:#x}+{:#x}: mixes slack-resident \
                     and past-base sections — the splice pass consumed the slack part \
                     and the past-base bytes have nowhere to go. Unsupported layout; \
                     put past-base (RAM-resident) sections in their own segment.",
                    ov.p_memsz
                );
            }
            continue; // splice path handled it
        }
        if any_in_base {
            bail!(
                "overlay PT_LOAD at {load_v_start:#x}+{:#x}: contains \
                 sections that overlap a non-slack base PT_LOAD",
                ov.p_memsz
            );
        }
        if !any_outside_base {
            continue;
        }
        // Trim the LOAD to start at the first PROGBITS section's
        // vaddr. ld page-aligns p_vaddr down by 0x1000 and may also
        // include leading NOBITS (the IRAM blocker), neither of which
        // need to be appended.
        let mut trimmed = *ov;
        if let Some(content_start) = first_progbits_vaddr
            && content_start > ov.p_vaddr
        {
            let trim = content_start - ov.p_vaddr;
            trimmed.p_offset += trim;
            trimmed.p_vaddr += trim;
            trimmed.p_paddr += trim;
            trimmed.p_filesz = trimmed.p_filesz.saturating_sub(trim);
            trimmed.p_memsz = trimmed.p_memsz.saturating_sub(trim);
        }
        append_loads.push(trimmed);
    }

    // Unwind coverage: overlay FDEs were spliced into the rodata slack
    // above; the runtime finds FDEs through the single PT_GNU_EH_FRAME
    // table, which was built at base link and can't know them. Merge
    // base's and overlay's `.eh_frame_hdr` tables into a fresh table in
    // free rodata slack and repoint the phdr. No-op when either side
    // has nothing (xtensa/bare-metal: no PT_GNU_EH_FRAME).
    if let Some((base_n, ov_n)) =
        merge_unwind_tables(&mut out, &mut base_phdrs, class, &overlay_obj, &slack_regions)?
    {
        crate::telemetry::note(
            output_path,
            &format!(
                "graft combine: merged .eh_frame_hdr — {base_n} base + {ov_n} overlay FDE entries"
            ),
        );
    }

    // Debug info: concatenate overlay's `.debug_*` contributions after
    // base's (the overlay linked them concatenation-addressed — see
    // merge_debug_sections). Non-alloc: file-level only, the loaded
    // image is untouched.
    let (dbg_merged, dbg_bytes) = merge_debug_sections(
        &mut out,
        &base_obj_for_slack,
        &overlay_obj,
        overlay_bytes,
        class,
        output_path,
    )?;
    if dbg_merged > 0 {
        crate::telemetry::note(
            output_path,
            &format!(
                "graft combine: merged {dbg_merged} debug section(s), {dbg_bytes} bytes appended"
            ),
        );
    }

    // Symbol table: append the overlay's slack/appended-load symbols so
    // symtab-only consumers (nm, addr2line -f, nearest-symbol sweeps)
    // name grafted code — see merge_symtab. Non-alloc, file-level only.
    let (syms_added, sym_bytes) = merge_symtab(
        &mut out,
        overlay_bytes,
        class,
        &slack_regions,
        &append_loads,
        output_path,
    )?;
    if syms_added > 0 {
        crate::telemetry::note(
            output_path,
            &format!(
                "graft combine: merged {syms_added} overlay symbol(s) into .symtab \
                 ({sym_bytes} bytes appended)"
            ),
        );
    }

    // Trampoline on the entry symbol, applied to the splice-modified
    // buffer.
    let manifest_bytes = elf_attach::read_section(base_bytes, metadata::SECTION_MANIFEST)?
        .ok_or_else(|| anyhow!("{}: no {}", base_path.display(), metadata::SECTION_MANIFEST))?;
    let manifest = metadata::decode_manifest(manifest_bytes)?;
    // Pairing check: the overlay carries the base_abi it was linked
    // against. A different base can pass every geometric check (same
    // slack layout family) while every anchored address is stale.
    // Absent stamp = pre-v12 or empty-closure overlay; skip.
    if let Some(stamp_bytes) =
        elf_attach::read_section(overlay_bytes, metadata::SECTION_OVERLAY_STAMP)?
        && let Ok(stamp) = metadata::decode_overlay_stamp(stamp_bytes)
        && stamp.base_abi != manifest.base_abi
    {
        bail!(
            "{} was linked against a different base (build-id mismatch with {}) — \
             combining would bind every anchor to stale addresses",
            overlay_path.display(),
            base_path.display(),
        );
    }
    let entry = manifest.entry_symbol.as_str();

    let e_machine = u16::from_le_bytes(base_bytes[18..20].try_into().unwrap());
    let (base_entry_addr, base_entry_size) = find_text_def(&base_obj_for_slack, entry)
        .ok_or_else(|| anyhow!("entry symbol {entry:?} not defined in base"))?;
    let trampolines: Vec<Trampoline> = match find_text_def(&overlay_obj, entry) {
        Some((overlay_addr, overlay_size)) => {
            // The patch overwrites tramp_size bytes at base's entry;
            // refuse rather than clobber a neighboring function. st_size
            // 0 (hand asm without .size) is indistinguishable from
            // "tiny" — refuse that too, loudly, instead of guessing.
            let tramp_size = crate::arch::trampoline_size(e_machine)? as u64;
            if base_entry_size < tramp_size {
                bail!(
                    "entry symbol {entry:?} is {base_entry_size} bytes in base — smaller than \
                     the {tramp_size}-byte trampoline; patching would overwrite the next function"
                );
            }
            let prologue_size = crate::arch::trampoline_prologue_size(e_machine)?;
            if prologue_size > 0 {
                // The l32r literal at from+8 needs a 4-byte-aligned
                // patch site (arch.rs layout).
                if base_entry_addr % 4 != 0 {
                    bail!(
                        "entry symbol {entry:?} at {base_entry_addr:#x} is not 4-byte aligned — \
                         the xtensa trampoline's l32r literal requires it"
                    );
                }
                if overlay_size != 0 && overlay_size < prologue_size as u64 {
                    bail!(
                        "entry symbol {entry:?} is {overlay_size} bytes in overlay — smaller \
                         than its own {prologue_size}-byte entry instruction?"
                    );
                }
            }
            // The prologue the trampoline executes must be the OVERLAY
            // function's own `entry` instruction: it encodes the frame
            // size of the body we jump into at overlay+3. Base's copy
            // allocates base's (possibly smaller) frame — running the
            // new body on it silently corrupts the stack.
            let prologue = if prologue_size > 0 {
                read_bytes_at_vaddr(&overlay_obj, overlay_addr, prologue_size)
                    .with_context(|| format!("read overlay entry prologue for {entry:?}"))?
            } else {
                Vec::new()
            };
            vec![Trampoline {
                name: entry.to_string(),
                base_addr: base_entry_addr,
                overlay_addr,
                prologue,
            }]
        }
        None => Vec::new(),
    };

    if trampolines.is_empty() && total_spliced == 0 && append_loads.is_empty() {
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
        apply_trampolines(&mut out, &base_phdrs, &trampolines, e_machine)?;
    }

    let mut appended_filesz: u64 = 0;
    if !append_loads.is_empty() {
        let new_loads =
            append_pt_loads(&mut out, overlay_bytes, &append_loads, &base_phdrs, class)?;
        appended_filesz = new_loads.iter().map(|p| p.p_filesz).sum();
        if overlay_vaddr_first == 0
            && let Some(p) = new_loads.first()
        {
            overlay_vaddr_first = p.p_vaddr;
        }
    }

    let ov_loads: Vec<Phdr> = ov_phdrs.iter().copied().filter(|p| p.p_type == PT_LOAD).collect();
    refresh_build_id(
        &mut out,
        &base_obj_for_slack,
        &base_loads,
        &overlay_obj,
        &ov_loads,
        overlay_bytes,
    )?;

    write_executable(output_path, &out)?;

    Ok(Stats {
        trampolines,
        overlay_load_size: total_spliced + appended_filesz,
        overlay_vaddr: overlay_vaddr_first,
        combined_size: out.len() as u64,
    })
}

/// Append a set of overlay PT_LOADs to `out`, extend the PHT, and add
/// matching SHT entries so espflash's section-walking image builder
/// emits image segments for them. Used by the splice path for
/// RAM-resident segments that legitimately fall past base (e.g. xtensa
/// `.rwtext` copied from flash to IRAM at boot).
///
/// Keeps `p_memsz = p_filesz` and writes no NOBITS-filling zeros: the
/// firmware bootloader doesn't care about AT_PHDR, and zero-padding an
/// appended LOAD to overlay's full `memsz` would overflow `dram2_seg`
/// into heap territory (overlay's `.stack` is a NOBITS region absorbing
/// all of RWDATA).
fn append_pt_loads(
    out: &mut Vec<u8>,
    overlay_bytes: &[u8],
    overlay_loads: &[Phdr],
    base_phdrs: &[Phdr],
    class: ElfClass,
) -> Result<Vec<Phdr>> {
    let mut new_loads: Vec<Phdr> = Vec::with_capacity(overlay_loads.len());
    for ov_load in overlay_loads {
        align_up(out, 0x1000);
        let new_offset = out.len() as u64;
        let load_data = &overlay_bytes
            [ov_load.p_offset as usize..(ov_load.p_offset + ov_load.p_filesz) as usize];
        out.extend_from_slice(load_data);
        new_loads.push(Phdr {
            p_type: PT_LOAD,
            p_flags: ov_load.p_flags,
            p_offset: new_offset,
            p_vaddr: ov_load.p_vaddr,
            p_paddr: ov_load.p_vaddr,
            p_filesz: ov_load.p_filesz,
            p_memsz: ov_load.p_filesz,
            p_align: 0x1000,
        });
    }

    align_up(out, 8);
    let new_phoff = out.len() as u64;
    let new_phnum = base_phdrs.len() + new_loads.len();

    for p in base_phdrs.iter().chain(new_loads.iter()) {
        out.extend_from_slice(&p.to_le_bytes(class));
    }

    let ho = class.header_offsets();
    match ho.e_phoff_size {
        4 => out[ho.e_phoff..ho.e_phoff + 4].copy_from_slice(&(new_phoff as u32).to_le_bytes()),
        8 => out[ho.e_phoff..ho.e_phoff + 8].copy_from_slice(&new_phoff.to_le_bytes()),
        n => bail!("unexpected e_phoff_size {n}"),
    }
    out[ho.e_phnum..ho.e_phnum + 2].copy_from_slice(&(new_phnum as u16).to_le_bytes());

    add_overlay_section_headers(out, &new_loads, class)?;
    Ok(new_loads)
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
    /// The OVERLAY entry function's first `trampoline_prologue_size`
    /// bytes (xtensa: its `entry` instruction, carrying the frame size
    /// of the body the trampoline jumps into). Empty on targets with
    /// no preserved prologue.
    pub prologue: Vec<u8>,
}

/// Locate an image's build-id bytes: the window between
/// `__build_id_start` and `__build_id_end` minus the 16-byte ELF note
/// header (esp-idf linker-script convention; same layout the reference
/// ESP32 application's `read_deploy_bin_build_id` reads). Returns (file_offset, id_len).
fn build_id_window(obj: &object::File, loads: &[Phdr]) -> Result<Option<(usize, usize)>> {
    use object::{Object, ObjectSymbol};

    let mut start = None;
    let mut end = None;
    for sym in obj.symbols() {
        match sym.name() {
            Ok("__build_id_start") => start = Some(sym.address()),
            Ok("__build_id_end") => end = Some(sym.address()),
            _ => {}
        }
    }
    let (Some(start), Some(end)) = (start, end) else {
        return Ok(None); // no build-id convention in this image
    };
    let id_vaddr = start + 16;
    if end <= id_vaddr {
        bail!("build-id window malformed: [{start:#x}, {end:#x})");
    }
    let load = loads
        .iter()
        .find(|p| id_vaddr >= p.p_vaddr && end <= p.p_vaddr + p.p_filesz)
        .ok_or_else(|| anyhow!("build-id window outside every PT_LOAD"))?;
    let off = (load.p_offset + (id_vaddr - load.p_vaddr)) as usize;
    Ok(Some((off, (end - id_vaddr) as usize)))
}

/// Refresh the combined image's build id:
/// `new_id = blake3(base_id ‖ overlay_id)[..len]` — the overlay link
/// runs through the same linker script, so overlay.elf mints its own
/// build-id; composing the two published identities is deterministic
/// per (base, overlay) and chains across chained overlays. A base with
/// a window and an overlay without one is a hard error — that means
/// the overlay link diverged from the base's script, and a silently
/// unchanged id would defeat every downstream consumer. Images whose
/// base has no window (fixtures, native targets) are left untouched.
fn refresh_build_id(
    out: &mut [u8],
    base_obj: &object::File,
    base_loads: &[Phdr],
    overlay_obj: &object::File,
    overlay_loads: &[Phdr],
    overlay_bytes: &[u8],
) -> Result<()> {
    let Some((off, id_len)) = build_id_window(base_obj, base_loads)? else {
        return Ok(());
    };
    let Some((ov_off, ov_len)) = build_id_window(overlay_obj, overlay_loads)? else {
        bail!(
            "base image has a build-id window but overlay.elf does not — \
             the overlay link did not emit a build-id (script drift?)"
        );
    };

    let old_id = out[off..off + id_len].to_vec();
    let mut h = blake3::Hasher::new();
    h.update(&old_id);
    h.update(&overlay_bytes[ov_off..ov_off + ov_len]);
    let mut new_id = vec![0u8; id_len];
    h.finalize_xof().fill(&mut new_id);
    out[off..off + id_len].copy_from_slice(&new_id);

    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    eprintln!(
        "graft combine: build-id {}… -> {}… ({id_len} bytes)",
        &hex(&old_id)[..16],
        &hex(&new_id)[..16],
    );
    Ok(())
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

fn read_slack_regions(base: &object::File, base_bytes: &[u8]) -> Result<Vec<SlackRegion>> {
    use object::ObjectSymbol;
    let mut text: Option<(u64, u64)> = None;
    let mut rodata: Option<(u64, u64)> = None;
    let mut data: Option<(u64, u64)> = None;
    let mut tls: Option<(u64, u64)> = None;
    for sym in base.symbols() {
        let Ok(name) = sym.name() else { continue };
        match name {
            crate::slack::TEXT_SYMBOL => text = Some((sym.address(), sym.size())),
            crate::slack::RODATA_SYMBOL => rodata = Some((sym.address(), sym.size())),
            crate::slack::DATA_SYMBOL => data = Some((sym.address(), sym.size())),
            // STT_TLS: address() is a template-relative offset, not a
            // vaddr — translated below once PT_TLS is known.
            crate::slack::TLS_SYMBOL => tls = Some((sym.address(), sym.size())),
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
    if let Some((s, l)) = data {
        regions.push(SlackRegion { name: "data", start: s, len: l });
    }
    if let Some((off, l)) = tls
        && let Some(t) = pt_tls(base_bytes)?
    {
        regions.push(SlackRegion { name: "tls", start: t.vaddr + off, len: l });
    }
    if regions.is_empty() {
        bail!(
            "base ELF has no GRAFT_*_SLACK symbols — splice mode requires \
             at least one slack region"
        );
    }
    Ok(regions)
}

/// Merge the overlay's `.debug_*` sections into base's, byte-splice
/// style: the overlay layout script assigned each debug output section
/// ADDRESS = size of base's same-named section, so ld already resolved
/// every cross-section DWARF offset (strp, stmt_list, abbrev_offset,
/// DWARF5 bases) as-if the overlay's contribution sat concatenated
/// after base's. This function performs exactly that concatenation:
/// `base_bytes ++ overlay_bytes` appended at EOF, base's shdr repointed
/// (sh_offset/sh_size patched in place — non-alloc, so no phdr or
/// vaddr impact; the flashed/loaded image is untouched). No DWARF is
/// parsed, here or anywhere.
///
/// The old base debug bytes become dead file space — the cost of never
/// parsing DWARF. Overlay-only debug sections (base lacks the name)
/// are skipped with a note: appending a *new* section needs an SHT
/// rewrite, and same-toolchain links produce the same section set, so
/// this arm should stay cold.
///
/// Returns `(sections_merged, bytes_appended)`.
fn merge_debug_sections(
    out: &mut Vec<u8>,
    base_obj: &object::File,
    overlay_obj: &object::File,
    overlay_bytes: &[u8],
    class: ElfClass,
    output_path: &Path,
) -> Result<(usize, u64)> {
    use object::ObjectSection;
    // ELF header SHT geometry (not in HeaderOffsets — phdr-only there).
    let (e_shoff_pos, e_shoff, shentsize) = match class {
        ElfClass::Elf32 => {
            let off = u32::from_le_bytes(out[0x20..0x24].try_into().unwrap()) as u64;
            let ent = u16::from_le_bytes(out[0x2e..0x30].try_into().unwrap()) as usize;
            (0x20usize, off, ent)
        }
        ElfClass::Elf64 => {
            let off = u64::from_le_bytes(out[0x28..0x30].try_into().unwrap());
            let ent = u16::from_le_bytes(out[0x3a..0x3c].try_into().unwrap()) as usize;
            (0x28usize, off, ent)
        }
    };
    let _ = e_shoff_pos;
    if e_shoff == 0 {
        bail!("base ELF has no section header table — cannot merge debug sections");
    }
    let mut merged = 0usize;
    let mut appended: u64 = 0;
    for ov in overlay_obj.sections() {
        let Ok(name) = ov.name() else { continue };
        if !name.starts_with(".debug_") || name == ".debug_gdb_scripts" {
            continue;
        }
        let Some((ov_off, ov_size)) = ov.file_range() else { continue };
        if ov_size == 0 {
            continue;
        }
        let Some(base_sec) = base_obj.section_by_name(name) else {
            crate::telemetry::note(
                output_path,
                &format!(
                    "graft combine: overlay-only debug section {name} ({ov_size} bytes) \
                     not merged into the combined image (base lacks it; still present in \
                     overlay.elf)"
                ),
            );
            continue;
        };
        let base_size = base_sec.size();
        if ov.address() != base_size {
            bail!(
                "debug-merge contract violated: overlay {name} linked at address {:#x} \
                 but base's {name} is {base_size:#x} bytes — the layout script's \
                 concatenation addresses drifted; refusing to emit misoffset DWARF",
                ov.address()
            );
        }
        let Some((base_off, base_fsize)) = base_sec.file_range() else { continue };
        // Concatenated section content must be internally positioned
        // exactly as the addresses claim: base at 0, overlay at
        // base_size.
        if base_fsize != base_size {
            bail!("debug section {name}: base file size {base_fsize:#x} != sh_size {base_size:#x}");
        }
        let align = base_sec.align().max(1) as usize;
        while out.len() % align != 0 {
            out.push(0);
        }
        let new_off = out.len() as u64;
        out.extend_from_within(base_off as usize..(base_off + base_fsize) as usize);
        out.extend_from_slice(&overlay_bytes[ov_off as usize..(ov_off + ov_size) as usize]);
        // Patch base's shdr in place. `SectionIndex.0` is the ELF
        // section index (null entry included), so the entry position is
        // direct.
        let slot = e_shoff as usize + base_sec.index().0 * shentsize;
        match class {
            ElfClass::Elf32 => {
                out[slot + 0x10..slot + 0x14]
                    .copy_from_slice(&u32::try_from(new_off)?.to_le_bytes());
                out[slot + 0x14..slot + 0x18]
                    .copy_from_slice(&u32::try_from(base_size + ov_size)?.to_le_bytes());
            }
            ElfClass::Elf64 => {
                out[slot + 0x18..slot + 0x20].copy_from_slice(&new_off.to_le_bytes());
                out[slot + 0x20..slot + 0x28]
                    .copy_from_slice(&(base_size + ov_size).to_le_bytes());
            }
        }
        merged += 1;
        appended += base_fsize + ov_size;
    }
    Ok((merged, appended))
}

/// Raw class-aware section header, read straight from the file bytes.
/// The object crate's parsed view is deliberately not used here: symtab
/// surgery needs exact field offsets for in-place patching, and the
/// same decode must run against both the combined buffer and
/// overlay.elf.
struct RawShdr {
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

fn read_shdrs(bytes: &[u8], class: ElfClass) -> Result<(u64, usize, Vec<RawShdr>)> {
    let (e_shoff, shentsize, shnum) = match class {
        ElfClass::Elf32 => (
            u32::from_le_bytes(bytes[0x20..0x24].try_into().unwrap()) as u64,
            u16::from_le_bytes(bytes[0x2e..0x30].try_into().unwrap()) as usize,
            u16::from_le_bytes(bytes[0x30..0x32].try_into().unwrap()) as usize,
        ),
        ElfClass::Elf64 => (
            u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()),
            u16::from_le_bytes(bytes[0x3a..0x3c].try_into().unwrap()) as usize,
            u16::from_le_bytes(bytes[0x3c..0x3e].try_into().unwrap()) as usize,
        ),
    };
    if e_shoff == 0 || shnum == 0 {
        bail!("ELF has no section header table");
    }
    let mut shdrs = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let s = e_shoff as usize + i * shentsize;
        let w32 = |a: usize| u32::from_le_bytes(bytes[s + a..s + a + 4].try_into().unwrap());
        let w64 = |a: usize| u64::from_le_bytes(bytes[s + a..s + a + 8].try_into().unwrap());
        shdrs.push(match class {
            ElfClass::Elf32 => RawShdr {
                sh_type: w32(0x4),
                sh_flags: w32(0x8) as u64,
                sh_addr: w32(0xc) as u64,
                sh_offset: w32(0x10) as u64,
                sh_size: w32(0x14) as u64,
                sh_link: w32(0x18),
                sh_entsize: w32(0x24) as u64,
            },
            ElfClass::Elf64 => RawShdr {
                sh_type: w32(0x4),
                sh_flags: w64(0x8),
                sh_addr: w64(0x10),
                sh_offset: w64(0x18),
                sh_size: w64(0x20),
                sh_link: w32(0x28),
                sh_entsize: w64(0x38),
            },
        });
    }
    Ok((e_shoff, shentsize, shdrs))
}

/// Raw symtab entry, class-independent in-memory form.
#[derive(Clone, Copy)]
struct RawSym {
    name_off: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    shndx: u16,
}

fn sym_entsize(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => 16,
        ElfClass::Elf64 => 24,
    }
}

fn decode_syms(table: &[u8], class: ElfClass) -> Vec<RawSym> {
    let ent = sym_entsize(class) as usize;
    table
        .chunks_exact(ent)
        .map(|c| match class {
            ElfClass::Elf32 => RawSym {
                name_off: u32::from_le_bytes(c[0..4].try_into().unwrap()),
                value: u32::from_le_bytes(c[4..8].try_into().unwrap()) as u64,
                size: u32::from_le_bytes(c[8..12].try_into().unwrap()) as u64,
                info: c[12],
                other: c[13],
                shndx: u16::from_le_bytes(c[14..16].try_into().unwrap()),
            },
            ElfClass::Elf64 => RawSym {
                name_off: u32::from_le_bytes(c[0..4].try_into().unwrap()),
                info: c[4],
                other: c[5],
                shndx: u16::from_le_bytes(c[6..8].try_into().unwrap()),
                value: u64::from_le_bytes(c[8..16].try_into().unwrap()),
                size: u64::from_le_bytes(c[16..24].try_into().unwrap()),
            },
        })
        .collect()
}

fn encode_sym(out: &mut Vec<u8>, s: &RawSym, class: ElfClass) {
    match class {
        ElfClass::Elf32 => {
            out.extend_from_slice(&s.name_off.to_le_bytes());
            out.extend_from_slice(&(s.value as u32).to_le_bytes());
            out.extend_from_slice(&(s.size as u32).to_le_bytes());
            out.push(s.info);
            out.push(s.other);
            out.extend_from_slice(&s.shndx.to_le_bytes());
        }
        ElfClass::Elf64 => {
            out.extend_from_slice(&s.name_off.to_le_bytes());
            out.push(s.info);
            out.push(s.other);
            out.extend_from_slice(&s.shndx.to_le_bytes());
            out.extend_from_slice(&s.value.to_le_bytes());
            out.extend_from_slice(&s.size.to_le_bytes());
        }
    }
}

/// Merge the overlay's defined symbols into the combined `.symtab` so
/// symtab-only consumers — nm, `addr2line -f`, nearest-preceding-symbol
/// sweeps — resolve slack/appended pcs to real names instead of
/// whatever base symbol happens to precede the slack region. DWARF
/// answers gdb/coredump queries (`merge_debug_sections`); this answers
/// every tool that never reads DWARF.
///
/// Mechanics mirror the debug merge: rebuild `.symtab` and `.strtab`
/// at EOF and repoint their shdrs (both non-alloc — the loaded/flashed
/// image is untouched; the old tables become dead file space). The
/// rebuilt table is `[base locals] ++ [overlay locals] ++
/// [base globals] ++ [overlay globals]` with `sh_info` recomputed, so
/// the locals-before-globals invariant holds. Base entries are copied
/// verbatim — including the stale symbols of edited functions' base
/// copies, the same two-copy semantics the DWARF merge ships.
///
/// Overlay symbols come raw from overlay.elf's symtab (full
/// st_info/st_other fidelity), filtered to: defined, not
/// SECTION/FILE, not TLS (template-relative st_value would need
/// PT_TLS translation and the consumers this serves sweep text/data),
/// name not graft-internal, and st_value inside a slack region or an
/// appended past-base PT_LOAD. st_shndx is retargeted to the combined
/// section covering the address; SHN_ABS when nothing does (appended
/// loads have segment identity, not section identity).
///
/// Skipped with a note when any section references the symtab via
/// sh_link (REL/RELA/GROUP/SYMTAB_SHNDX/HASH): those hold symbol
/// *indices*, which the rebuild shifts. Fully linked static
/// executables — the only input combine accepts — don't carry them.
///
/// Returns `(symbols_added, bytes_appended)`.
fn merge_symtab(
    out: &mut Vec<u8>,
    overlay_bytes: &[u8],
    class: ElfClass,
    slack_regions: &[SlackRegion],
    append_loads: &[Phdr],
    output_path: &Path,
) -> Result<(usize, u64)> {
    let (e_shoff, shentsize, shdrs) = read_shdrs(out, class).context("combined SHT")?;
    let Some(symtab_idx) = shdrs.iter().position(|s| s.sh_type == SHT_SYMTAB) else {
        crate::telemetry::note(output_path, "graft combine: base has no .symtab — symbol merge skipped");
        return Ok((0, 0));
    };
    if let Some(referrer) = shdrs
        .iter()
        .position(|s| s.sh_type != SHT_NULL && s.sh_link as usize == symtab_idx)
    {
        crate::telemetry::note(
            output_path,
            &format!(
                "graft combine: section {referrer} references .symtab by index \
                 (sh_link) — symbol merge skipped to keep indices stable"
            ),
        );
        return Ok((0, 0));
    }
    let symtab = &shdrs[symtab_idx];
    let strtab_idx = symtab.sh_link as usize;
    let strtab = shdrs
        .get(strtab_idx)
        .ok_or_else(|| anyhow!(".symtab sh_link {strtab_idx} out of range"))?;
    if symtab.sh_entsize != sym_entsize(class) {
        bail!(
            ".symtab entsize {} != expected {} — refusing symbol merge",
            symtab.sh_entsize,
            sym_entsize(class)
        );
    }
    let base_syms = decode_syms(
        &out[symtab.sh_offset as usize..(symtab.sh_offset + symtab.sh_size) as usize],
        class,
    );
    let base_strtab =
        out[strtab.sh_offset as usize..(strtab.sh_offset + strtab.sh_size) as usize].to_vec();

    // Overlay side: raw symtab + strtab from overlay.elf.
    let (_, _, ov_shdrs) = read_shdrs(overlay_bytes, class).context("overlay SHT")?;
    let Some(ov_symtab) = ov_shdrs.iter().find(|s| s.sh_type == SHT_SYMTAB) else {
        return Ok((0, 0));
    };
    let ov_strtab = ov_shdrs
        .get(ov_symtab.sh_link as usize)
        .ok_or_else(|| anyhow!("overlay .symtab sh_link out of range"))?;
    let ov_syms = decode_syms(
        &overlay_bytes
            [ov_symtab.sh_offset as usize..(ov_symtab.sh_offset + ov_symtab.sh_size) as usize],
        class,
    );
    let ov_names =
        &overlay_bytes[ov_strtab.sh_offset as usize..(ov_strtab.sh_offset + ov_strtab.sh_size) as usize];
    let name_of = |off: u32| -> Option<&str> {
        let start = off as usize;
        let end = ov_names[start..].iter().position(|&b| b == 0)? + start;
        std::str::from_utf8(&ov_names[start..end]).ok()
    };

    let in_span = |v: u64| {
        slack_regions.iter().any(|r| v >= r.start && v < r.start + r.len)
            || append_loads.iter().any(|p| v >= p.p_vaddr && v < p.p_vaddr + p.p_memsz)
    };
    // Combined section covering an address → st_shndx retarget.
    let covering = |v: u64| -> u16 {
        shdrs
            .iter()
            .position(|s| {
                s.sh_flags & u64::from(SHF_ALLOC) != 0
                    && v >= s.sh_addr
                    && v < s.sh_addr + s.sh_size
            })
            .map_or(SHN_ABS, |i| i as u16)
    };

    let mut adds: Vec<RawSym> = Vec::new();
    let mut new_strtab = base_strtab;
    for s in ov_syms.iter().skip(1) {
        let ty = s.info & 0xf;
        if ty == STT_SECTION || ty == STT_FILE || ty == STT_TLS {
            continue;
        }
        if s.shndx == SHN_UNDEF as u16 || s.shndx >= SHN_LORESERVE as u16 {
            continue;
        }
        if !in_span(s.value) {
            continue;
        }
        let Some(name) = name_of(s.name_off) else { continue };
        if name.is_empty() || name.starts_with("__graft") || name.starts_with("_graft") {
            continue;
        }
        let name_off = u32::try_from(new_strtab.len())?;
        new_strtab.extend_from_slice(name.as_bytes());
        new_strtab.push(0);
        adds.push(RawSym { name_off, shndx: covering(s.value), ..*s });
    }
    if adds.is_empty() {
        return Ok((0, 0));
    }

    // Rebuild: locals (base order, null entry first) ++ overlay locals
    // ++ base globals ++ overlay globals.
    let is_local = |s: &RawSym| s.info >> 4 == 0;
    let mut table: Vec<u8> = Vec::with_capacity(
        (base_syms.len() + adds.len()) * sym_entsize(class) as usize,
    );
    let mut n_locals = 0usize;
    for s in base_syms.iter().filter(|s| is_local(s)).chain(adds.iter().filter(|s| is_local(s))) {
        encode_sym(&mut table, s, class);
        n_locals += 1;
    }
    for s in base_syms.iter().filter(|s| !is_local(s)).chain(adds.iter().filter(|s| !is_local(s))) {
        encode_sym(&mut table, s, class);
    }

    // Append both tables at EOF; patch the two shdrs in place.
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let symtab_off = out.len() as u64;
    out.extend_from_slice(&table);
    let strtab_off = out.len() as u64;
    out.extend_from_slice(&new_strtab);
    let appended = (table.len() + new_strtab.len()) as u64;

    let patch = |out: &mut Vec<u8>, idx: usize, off: u64, size: u64, info: Option<u32>| -> Result<()> {
        let slot = e_shoff as usize + idx * shentsize;
        match class {
            ElfClass::Elf32 => {
                out[slot + 0x10..slot + 0x14].copy_from_slice(&u32::try_from(off)?.to_le_bytes());
                out[slot + 0x14..slot + 0x18].copy_from_slice(&u32::try_from(size)?.to_le_bytes());
                if let Some(i) = info {
                    out[slot + 0x1c..slot + 0x20].copy_from_slice(&i.to_le_bytes());
                }
            }
            ElfClass::Elf64 => {
                out[slot + 0x18..slot + 0x20].copy_from_slice(&off.to_le_bytes());
                out[slot + 0x20..slot + 0x28].copy_from_slice(&size.to_le_bytes());
                if let Some(i) = info {
                    out[slot + 0x2c..slot + 0x30].copy_from_slice(&i.to_le_bytes());
                }
            }
        }
        Ok(())
    };
    patch(out, symtab_idx, symtab_off, table.len() as u64, Some(u32::try_from(n_locals)?))?;
    patch(out, strtab_idx, strtab_off, new_strtab.len() as u64, None)?;

    Ok((adds.len(), appended))
}

/// Merge base's and the overlay's `.eh_frame_hdr` lookup tables and
/// repoint `PT_GNU_EH_FRAME` at the merged copy (written into free
/// rodata slack). See `ehframe.rs` for the design. Returns
/// `(base_entries, overlay_entries_kept)` when a merge happened.
///
/// Overlay entries are filtered to pcs inside the *text slack*: prune
/// keeps whole object-granular `.eh_frame` sections, so the overlay's
/// table also lists FDEs whose pc anchored to base addresses (unchanged
/// functions of edited objects) — coverage base's own table already
/// provides. Slack membership, not base coverage, is the filter, so
/// FDEs for genuinely new code always survive it.
fn merge_unwind_tables(
    out: &mut [u8],
    base_phdrs: &mut [Phdr],
    class: ElfClass,
    overlay_obj: &object::File,
    slack_regions: &[SlackRegion],
) -> Result<Option<(usize, usize)>> {
    use object::ObjectSection;
    let Some(eh_idx) = base_phdrs.iter().position(|p| p.p_type == PT_GNU_EH_FRAME) else {
        return Ok(None); // no unwinder lookup path in this image
    };
    let Some(ov_hdr_sec) = overlay_obj.section_by_name(".eh_frame_hdr") else {
        return Ok(None); // overlay carries no unwind info
    };
    if ov_hdr_sec.size() == 0 {
        return Ok(None);
    }
    let Some(text) = slack_regions.iter().find(|r| r.name == "text") else {
        return Ok(None); // nothing re-emitted into slack ⇒ nothing to cover
    };
    let ov_table = crate::ehframe::parse_hdr(ov_hdr_sec.data()?, ov_hdr_sec.address())?;
    let ov_entries: Vec<(u64, u64)> = ov_table
        .entries
        .iter()
        .copied()
        .filter(|&(pc, _)| pc >= text.start && pc < text.start + text.len)
        .collect();
    if ov_entries.is_empty() {
        return Ok(None); // every overlay FDE describes base-resident code
    }
    let Some(rodata) = slack_regions.iter().find(|r| r.name == "rodata") else {
        bail!("unwind merge needs a rodata slack region for the merged table");
    };
    // The kept entries' FDE records must live in the combined image —
    // i.e. inside the spliced rodata slack. Anywhere else means the
    // overlay layout drifted from the splice design; refuse.
    for &(pc, fde) in &ov_entries {
        if fde < rodata.start || fde >= rodata.start + rodata.len {
            bail!(
                "overlay FDE at {fde:#x} (pc {pc:#x}) lies outside the rodata \
                 slack — its bytes were not spliced into the combined image"
            );
        }
    }

    let base_eh = base_phdrs[eh_idx];
    let hdr_range = base_eh.p_offset as usize..(base_eh.p_offset + base_eh.p_filesz) as usize;
    let base_table = crate::ehframe::parse_hdr(&out[hdr_range], base_eh.p_vaddr)?;

    // Place the merged table after the last overlay byte spliced into
    // the rodata slack.
    let mut place = rodata.start;
    for sec in overlay_obj.sections() {
        let SectionFlags::Elf { sh_flags } = sec.flags() else { continue };
        if sh_flags & u64::from(SHF_ALLOC) == 0 || sec.size() == 0 {
            continue;
        }
        let (s, e) = (sec.address(), sec.address() + sec.size());
        if s >= rodata.start && e <= rodata.start + rodata.len {
            place = place.max(e);
        }
    }
    let table_vaddr = (place + 3) & !3;
    let merged = crate::ehframe::merge_entries(&base_table.entries, &ov_entries);
    let bytes = crate::ehframe::build_hdr(base_table.eh_frame_ptr, &merged, table_vaddr)?;
    if table_vaddr + bytes.len() as u64 > rodata.start + rodata.len {
        bail!(
            "merged .eh_frame_hdr ({} bytes at {table_vaddr:#x}) overflows the rodata \
             slack — raise rodata= in GRAFT_SLACK_LEN and rebuild base",
            bytes.len()
        );
    }
    let load = base_phdrs
        .iter()
        .find(|p| {
            p.p_type == PT_LOAD
                && table_vaddr >= p.p_vaddr
                && table_vaddr + bytes.len() as u64 <= p.p_vaddr + p.p_filesz
        })
        .ok_or_else(|| {
            anyhow!("merged .eh_frame_hdr vaddr {table_vaddr:#x} not inside a base PT_LOAD")
        })?;
    let off = (load.p_offset + (table_vaddr - load.p_vaddr)) as usize;
    out[off..off + bytes.len()].copy_from_slice(&bytes);

    // Repoint the phdr — in the caller's vec (used if the PHT gets
    // rewritten later by append_pt_loads) AND in the in-file PHT.
    let patched = Phdr {
        p_offset: off as u64,
        p_vaddr: table_vaddr,
        p_paddr: table_vaddr,
        p_filesz: bytes.len() as u64,
        p_memsz: bytes.len() as u64,
        ..base_eh
    };
    base_phdrs[eh_idx] = patched;
    let ho = class.header_offsets();
    let e_phoff = match ho.e_phoff_size {
        4 => u32::from_le_bytes(out[ho.e_phoff..ho.e_phoff + 4].try_into().unwrap()) as usize,
        8 => u64::from_le_bytes(out[ho.e_phoff..ho.e_phoff + 8].try_into().unwrap()) as usize,
        n => bail!("unexpected e_phoff_size {n}"),
    };
    let entsize = class.phdr_size();
    let slot = e_phoff + eh_idx * entsize;
    out[slot..slot + entsize].copy_from_slice(&patched.to_le_bytes(class));

    Ok(Some((base_table.entries.len(), ov_entries.len())))
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

/// The output ELF's PT_TLS geometry, shared by base (TLS symbol
/// address recovery), overlay (TLS map synthesis + geometry verify),
/// and combine. TLS symbols' st_values in a linked ELF are
/// *template-relative offsets*; `vaddr + st_value` is the template
/// byte's virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtTls {
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// A linked-ELF symtab value as a virtual address. STT_TLS symbols
/// carry template-relative offsets (see [`PtTls`]); everything else
/// already carries a vaddr. `None` for a TLS symbol in an ELF without
/// PT_TLS — there is no template to be relative to, so the value is
/// meaningless and the caller must skip the symbol. Every consumer of
/// final symtab addresses goes through here; treating a TLS st_value
/// as an address directly is the bug the map oracle caught twice.
pub fn symbol_vaddr(
    kind: object::SymbolKind,
    st_value: u64,
    tls_vaddr: Option<u64>,
) -> Option<u64> {
    if matches!(kind, object::SymbolKind::Tls) {
        tls_vaddr.map(|tv| tv + st_value)
    } else {
        Some(st_value)
    }
}

/// Read the PT_TLS program header from a linked ELF, if present.
pub fn pt_tls(elf_bytes: &[u8]) -> Result<Option<PtTls>> {
    let class = ElfClass::from_bytes(elf_bytes)?;
    let tls = read_program_headers(elf_bytes, class)?
        .into_iter()
        .find(|p| p.p_type == object::elf::PT_TLS)
        .map(|p| PtTls {
            vaddr: p.p_vaddr,
            filesz: p.p_filesz,
            memsz: p.p_memsz,
            align: p.p_align.max(1),
        });
    Ok(tls)
}

/// `(p_vaddr, p_memsz)` of every PT_LOAD in a linked ELF. memsz, not
/// filesz: anchors into `.bss` vaddrs are inside memsz only.
pub fn pt_load_spans(elf_bytes: &[u8]) -> Result<Vec<(u64, u64)>> {
    let class = ElfClass::from_bytes(elf_bytes)?;
    Ok(read_program_headers(elf_bytes, class)?
        .into_iter()
        .filter(|p| p.p_type == PT_LOAD && p.p_memsz > 0)
        .map(|p| (p.p_vaddr, p.p_memsz))
        .collect())
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

/// Find a defined text symbol; returns `(st_value, st_size)`.
fn find_text_def(elf: &object::File<'_>, name: &str) -> Option<(u64, u64)> {
    elf.symbols().find_map(|s| {
        if !s.is_definition() || !matches!(s.kind(), object::SymbolKind::Text) {
            return None;
        }
        if s.name().ok()? != name {
            return None;
        }
        Some((s.address(), s.size()))
    })
}

/// Read `len` bytes at virtual address `vaddr` out of an ELF's section
/// contents (used to pull the overlay entry function's first
/// instruction for the trampoline prologue).
fn read_bytes_at_vaddr(elf: &object::File<'_>, vaddr: u64, len: usize) -> Result<Vec<u8>> {
    use object::ObjectSection;
    for sec in elf.sections() {
        let (addr, size) = (sec.address(), sec.size());
        if vaddr >= addr && vaddr + len as u64 <= addr + size {
            let data = sec.data()?;
            let off = (vaddr - addr) as usize;
            if off + len <= data.len() {
                return Ok(data[off..off + len].to_vec());
            }
        }
    }
    bail!("no section contents cover {vaddr:#x}..+{len}");
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
        // Bound by the segment's file bytes, not just EOF: a patch near
        // segment end must not spill into the next segment's contents.
        if t.base_addr + tramp_size as u64 > seg.p_vaddr + seg.p_filesz {
            bail!(
                "trampoline {} ({} bytes) at {:#x} runs past its PT_LOAD's filesz",
                t.name,
                tramp_size,
                t.base_addr
            );
        }
        let file_off = (seg.p_offset + (t.base_addr - seg.p_vaddr)) as usize;
        if file_off + tramp_size > out.len() {
            bail!(
                "trampoline {} ({} bytes) patches past EOF",
                t.name,
                tramp_size
            );
        }
        // Sanity-check the patch site: base's entry function must open
        // with `entry` (opcode byte 0x36) — anything else means we're
        // patching the wrong place. (arch.rs makes the same check on
        // the overlay prologue we're about to install.)
        if prologue_size > 0 && out[file_off] != 0x36 {
            bail!(
                "trampoline {}: base entry at {:#x} does not start with an `entry` \
                 instruction (byte {:#04x})",
                t.name,
                t.base_addr,
                out[file_off]
            );
        }
        let bytes = crate::arch::trampoline(e_machine, t.base_addr, t.overlay_addr, &t.prologue)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn one_load(vaddr: u64, filesz: u64) -> Vec<Phdr> {
        vec![Phdr {
            p_type: PT_LOAD,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: vaddr,
            p_paddr: vaddr,
            p_filesz: filesz,
            p_memsz: filesz,
            p_align: 4,
        }]
    }

    fn tramp(base_addr: u64, prologue: &[u8]) -> Trampoline {
        Trampoline {
            name: "main".into(),
            base_addr,
            overlay_addr: 0x2000,
            prologue: prologue.to_vec(),
        }
    }

    /// The installed prologue must be the OVERLAY entry instruction —
    /// it encodes the frame size of the body the trampoline jumps
    /// into. Installing base's copy runs the new body on the old
    /// frame (silent stack corruption when the frame grew).
    #[test]
    fn xtensa_installs_overlay_entry_frame() {
        let base_prologue = [0x36, 0x81, 0x01]; // entry a1, 192
        let overlay_prologue = [0x36, 0xc1, 0x01]; // bigger frame
        let mut out = vec![0u8; 64];
        out[16..19].copy_from_slice(&base_prologue);
        apply_trampolines(
            &mut out,
            &one_load(0x1000, 64),
            &[tramp(0x1010, &overlay_prologue)],
            object::elf::EM_XTENSA,
        )
        .unwrap();
        assert_eq!(&out[16..19], &overlay_prologue);
    }

    /// A patch near segment end must refuse, not spill into the next
    /// segment's file bytes (EOF alone is not a bound).
    #[test]
    fn patch_past_filesz_refuses() {
        let mut out = vec![0u8; 4096];
        out[0] = 0x36;
        let err = apply_trampolines(
            &mut out,
            &one_load(0x1000, 16), // 16 bytes < 18-byte trampoline
            &[tramp(0x1000, &[0x36, 0x81, 0x01])],
            object::elf::EM_XTENSA,
        )
        .unwrap_err();
        assert!(err.to_string().contains("filesz"), "{err}");
    }

    /// Patch site whose first byte isn't `entry` (0x36) means we're
    /// aimed at the wrong place — refuse.
    #[test]
    fn non_entry_patch_site_refuses() {
        let mut out = vec![0u8; 64];
        out[0] = 0x90;
        let err = apply_trampolines(
            &mut out,
            &one_load(0x1000, 64),
            &[tramp(0x1000, &[0x36, 0x81, 0x01])],
            object::elf::EM_XTENSA,
        )
        .unwrap_err();
        assert!(err.to_string().contains("entry"), "{err}");
    }
}
