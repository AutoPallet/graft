//! Synthetic slack-`.o` injection.
//!
//! Reserves fixed-size, fixed-vaddr regions in base's `.text` and
//! `.rodata` for an overlay to splice into later. The `.o` carries:
//!
//!   - `.text.graft_slack`   — `0xFF`-filled SHT_PROGBITS, SHF_ALLOC|EXECINSTR
//!   - `.rodata.graft_slack` — `0xFF`-filled SHT_PROGBITS, SHF_ALLOC
//!
//! plus globals `GRAFT_TEXT_SLACK` / `GRAFT_RODATA_SLACK` covering each
//! section. The wildcards in the host linker scripts (esp-hal's
//! `*(.text .literal.*)` / `*(.rodata .rodata.*)`, ld's default
//! `*(.text.*)` / `*(.rodata.*)`) scoop these into base's normal output
//! sections — same layout as if the user had declared the statics in
//! their own source.
//!
//! Base mode adds the path to argv (treated as a regular input by the
//! real linker) plus `-Wl,--undefined=GRAFT_*_SLACK` so `--gc-sections`
//! doesn't drop them. Overlay mode reads the symbol values+sizes back
//! out of base.elf to drive its layout.

use anyhow::{Context, Result};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object, Symbol, SymbolSection},
};

/// 0xFF, not 0x00: NOR flash erase-state is 0xFF, so a fresh-erased
/// sector and an unwritten-overlay sector are bit-identical — a future
/// delta-flasher can skip already-erased sectors without writing
/// redundant bytes.
const SLACK_FILL_BYTE: u8 = 0xFF;

const DEFAULT_TEXT_LEN: u32 = 64 * 1024;
const DEFAULT_RODATA_LEN: u32 = 64 * 1024;
// Smaller default than text/rodata: writable static data in typical
// fixtures (format-piece slices, rust panic-info structs) is on the
// order of dozens to hundreds of bytes per closure. 4 KB covers
// common churn with room to spare; bumpable via env if a fixture
// needs more.
const DEFAULT_DATA_LEN: u32 = 4 * 1024;
// In-template TLS slack for thread-locals an overlay defines or
// re-emits (changed initializer). Deliberately tiny: every thread
// copies the template's filesz bytes at spawn, so this is a per-thread
// RAM cost. Bumpable via GRAFT_TLS_SLACK_LEN.
const DEFAULT_TLS_LEN: u32 = 64;
// TLS slack alignment — also a floor for the section's contribution
// to PT_TLS p_align. New thread-locals needing more than this trip
// the overlay's PT_TLS geometry check (loudly) rather than silently
// shifting every TP offset.
pub const TLS_SLACK_ALIGN: u64 = 16;

pub const TEXT_SYMBOL: &str = "GRAFT_TEXT_SLACK";
pub const RODATA_SYMBOL: &str = "GRAFT_RODATA_SLACK";
pub const DATA_SYMBOL: &str = "GRAFT_DATA_SLACK";
pub const TLS_SYMBOL: &str = "GRAFT_TLS_SLACK";

/// Validate the `GRAFT_OVERLAY_MODE` env var. Splice is the only overlay
/// layout strategy now: overlay's `.text` / `.rodata` are placed at
/// base-link-time-reserved slack vaddrs and byte-spliced into base's
/// existing segments, giving identical image shape and delta-flash
/// friendliness on every target. The old `append` mode (a fresh PT_LOAD
/// past base, with PHT/SHT rewrites) is gone — it was never usable on
/// xtensa (the bootloader maps only one IROM/DROM segment) and carried
/// the trickiest, least-tested ELF surgery in the codebase.
///
/// A stale `GRAFT_OVERLAY_MODE=append` (or any non-`splice` value) is a
/// hard error rather than a silent fall-through to splice, so an old
/// config can't quietly change layout strategy under the user.
pub fn ensure_splice_mode() -> anyhow::Result<()> {
    match std::env::var("GRAFT_OVERLAY_MODE").ok().as_deref() {
        None | Some("") | Some("splice") => Ok(()),
        Some("append") => anyhow::bail!(
            "GRAFT_OVERLAY_MODE=append is no longer supported — splice is the only \
             overlay mode. Unset GRAFT_OVERLAY_MODE."
        ),
        Some(other) => anyhow::bail!(
            "GRAFT_OVERLAY_MODE={other:?}: the only accepted value is `splice` (the default); \
             unset it."
        ),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SlackParams {
    pub text_len: u32,
    pub rodata_len: u32,
    pub data_len: u32,
    pub tls_len: u32,
}

impl SlackParams {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            text_len: env_u32("GRAFT_TEXT_SLACK_LEN")?.unwrap_or(DEFAULT_TEXT_LEN),
            rodata_len: env_u32("GRAFT_RODATA_SLACK_LEN")?.unwrap_or(DEFAULT_RODATA_LEN),
            data_len: env_u32("GRAFT_DATA_SLACK_LEN")?.unwrap_or(DEFAULT_DATA_LEN),
            tls_len: env_u32("GRAFT_TLS_SLACK_LEN")?.unwrap_or(DEFAULT_TLS_LEN),
        })
    }
}

/// `Ok(None)` if unset (caller uses its default); `Ok(Some(n))` if set
/// and parseable; `Err` if set but malformed. A typo'd slack size must
/// fail the build, not silently fall back to a default that's the wrong
/// size for the overlay — an undersized slack would surface much later
/// as a confusing "section will not fit in region" link error, and an
/// oversized one silently wastes flash.
fn env_u32(name: &str) -> Result<Option<u32>> {
    let Some(raw) = std::env::var_os(name) else { return Ok(None) };
    let s = raw
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{name}: value is not valid UTF-8"))?;
    let parsed = if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    parsed
        .map(Some)
        .map_err(|e| anyhow::anyhow!("{name}={s:?}: not a valid u32 ({e})"))
}

/// Build a relocatable ELF for the given architecture (mirrored from
/// one of the linker's input objects).
pub fn synthesize(architecture: Architecture, params: &SlackParams) -> Result<Vec<u8>> {
    let mut obj = Object::new(BinaryFormat::Elf, architecture, Endianness::Little);

    let text_id = obj.add_section(
        Vec::new(),
        b".text.graft_slack".to_vec(),
        SectionKind::Text,
    );
    obj.set_section_data(
        text_id,
        vec![SLACK_FILL_BYTE; params.text_len as usize],
        4,
    );

    let rodata_id = obj.add_section(
        Vec::new(),
        b".rodata.graft_slack".to_vec(),
        SectionKind::ReadOnlyData,
    );
    obj.set_section_data(
        rodata_id,
        vec![SLACK_FILL_BYTE; params.rodata_len as usize],
        4,
    );

    // Writable-data slack. Lands in base's `.data` via the standard
    // `*(.data .data.*)` wildcard, ends up loaded from flash to RAM
    // by the bootloader at boot like any other `.data`. Overlay's
    // `.data` later splices into the slack vaddr; the only cost vs
    // an unloaded section is N bytes of flash plus N bytes of RAM
    // permanently reserved.
    let data_id = obj.add_section(
        Vec::new(),
        b".data.graft_slack".to_vec(),
        SectionKind::Data,
    );
    obj.set_section_data(
        data_id,
        vec![SLACK_FILL_BYTE; params.data_len as usize],
        4,
    );

    obj.add_symbol(Symbol {
        name: TEXT_SYMBOL.as_bytes().to_vec(),
        value: 0,
        size: u64::from(params.text_len),
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });
    obj.add_symbol(Symbol {
        name: RODATA_SYMBOL.as_bytes().to_vec(),
        value: 0,
        size: u64::from(params.rodata_len),
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_id),
        flags: SymbolFlags::None,
    });
    obj.add_symbol(Symbol {
        name: DATA_SYMBOL.as_bytes().to_vec(),
        value: 0,
        size: u64::from(params.data_len),
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(data_id),
        flags: SymbolFlags::None,
    });

    // In-template TLS slack. Lands inside base's `.tdata` output via the
    // standard `*(.tdata .tdata.*)` wildcard, i.e. *inside the PT_TLS
    // template and inside its filesz* — both load-bearing: TP offsets
    // are end-anchored (variant 2), so the template can never grow at
    // combine time; slack must be reserved here, at base link, so
    // base's own offsets are computed with it present. filesz placement
    // gives splice file bytes to write initializers of overlay-defined
    // thread-locals into. ZERO-filled (not 0xFF like the other slacks):
    // these bytes are the per-thread initial image of whatever lands
    // there, and zero keeps un-spliced zero-init thread-locals correct
    // without any splice write.
    if params.tls_len > 0 {
        let tls_id = obj.add_section(
            Vec::new(),
            b".tdata.graft_slack".to_vec(),
            SectionKind::Tls,
        );
        obj.set_section_data(tls_id, vec![0u8; params.tls_len as usize], TLS_SLACK_ALIGN);
        obj.add_symbol(Symbol {
            name: TLS_SYMBOL.as_bytes().to_vec(),
            value: 0,
            size: u64::from(params.tls_len),
            kind: SymbolKind::Tls,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(tls_id),
            flags: SymbolFlags::None,
        });
    }

    obj.write().context("emit synthetic slack ELF")
}

/// Map a base ELF's `e_machine` to `object::Architecture`. Covers the
/// machines graft actually runs on; expand as new targets land.
pub fn architecture_from_e_machine(e_machine: u16) -> Result<Architecture> {
    use object::elf;
    Ok(match e_machine {
        elf::EM_X86_64 => Architecture::X86_64,
        elf::EM_386 => Architecture::I386,
        elf::EM_AARCH64 => Architecture::Aarch64,
        elf::EM_XTENSA => Architecture::Xtensa,
        m => anyhow::bail!("graft slack: unsupported e_machine {m:#x}"),
    })
}

/// Read e_machine from the first byte-readable input. Used by base
/// mode to mirror the target arch into the synthetic `.o`.
pub fn detect_architecture(inputs: &[std::path::PathBuf]) -> Result<Architecture> {
    for p in inputs {
        let Ok(bytes) = std::fs::read(p) else { continue };
        if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
            continue;
        }
        let e_machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
        return architecture_from_e_machine(e_machine);
    }
    anyhow::bail!("graft slack: no parseable ELF input to detect architecture from");
}
