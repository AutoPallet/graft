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

pub const TEXT_SYMBOL: &str = "GRAFT_TEXT_SLACK";
pub const RODATA_SYMBOL: &str = "GRAFT_RODATA_SLACK";

/// Overlay layout strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Overlay's `.text` / `.rodata` placed at base-link-time-reserved
    /// slack vaddrs and combined by byte-splicing into base's existing
    /// IROM/DROM segments. Required on xtensa; opt-in on x86 hosted
    /// (delta-flash benefits, identical image shape).
    Splice,
    /// Overlay placed at a fresh address past every base PT_LOAD;
    /// combine appends new PT_LOAD(s) and rewrites the PHT/SHT.
    /// Default on x86 hosted (no preallocation cap on overlay size).
    /// Not supported on xtensa (bootloader maps only one IROM/DROM
    /// segment per image).
    Append,
}

impl Mode {
    /// Resolve the active mode from the `GRAFT_OVERLAY_MODE` env var,
    /// falling back to a per-target default. `e_machine` is the base
    /// ELF's `e_machine` value.
    pub fn resolve(e_machine: u16) -> anyhow::Result<Self> {
        match std::env::var("GRAFT_OVERLAY_MODE").ok().as_deref() {
            Some("splice") => Ok(Mode::Splice),
            Some("append") => Ok(Mode::Append),
            Some(other) => anyhow::bail!(
                "GRAFT_OVERLAY_MODE={other:?}: expected `splice` or `append`"
            ),
            None => Ok(default_for_machine(e_machine)),
        }
    }
}

fn default_for_machine(e_machine: u16) -> Mode {
    if e_machine == object::elf::EM_XTENSA {
        Mode::Splice
    } else {
        Mode::Append
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SlackParams {
    pub text_len: u32,
    pub rodata_len: u32,
}

impl SlackParams {
    pub fn from_env() -> Self {
        Self {
            text_len: env_u32("GRAFT_TEXT_SLACK_LEN").unwrap_or(DEFAULT_TEXT_LEN),
            rodata_len: env_u32("GRAFT_RODATA_SLACK_LEN").unwrap_or(DEFAULT_RODATA_LEN),
        }
    }
}

fn env_u32(name: &str) -> Option<u32> {
    let s = std::env::var(name).ok()?;
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
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
