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

use anyhow::{Context, Result, bail};
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
// RAM cost. Bumpable via GRAFT_SLACK_LEN (`tls=`). Not used on
// xtensa — see `default_tls_len`.
const DEFAULT_TLS_LEN: u32 = 64;

/// xtensa defaults to NO TLS slack: both supported xtensa flavors'
/// linker scripts (esp-hal's linkall.x, esp-idf's) have no `*(.tdata*)`
/// scoop rule, so a TLS balloon gets orphan-placed — it once joined the
/// IROM LOAD, flipped it writable, and crash-looped the ESP ROM
/// bootloader with no link-time symptom. `check_slack_scooped` now
/// fails loud on that, but a mandatory `tls=0` knob on every xtensa
/// setup was pure friction. An explicit `GRAFT_SLACK_LEN=tls=N` still
/// re-enables the balloon for a script that does scoop `.tdata`.
fn default_tls_len(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::Xtensa => 0,
        _ => DEFAULT_TLS_LEN,
    }
}
// TLS slack alignment — also a floor for the section's contribution
// to PT_TLS p_align. New thread-locals needing more than this trip
// the overlay's PT_TLS geometry check (loudly) rather than silently
// shifting every TP offset.
pub const TLS_SLACK_ALIGN: u64 = 16;

pub const TEXT_SYMBOL: &str = "GRAFT_TEXT_SLACK";
pub const RODATA_SYMBOL: &str = "GRAFT_RODATA_SLACK";
pub const DATA_SYMBOL: &str = "GRAFT_DATA_SLACK";
pub const TLS_SYMBOL: &str = "GRAFT_TLS_SLACK";

/// The single env var that overrides slack region sizes. Its value is a
/// comma-separated list of `region=len` pairs, e.g.
/// `GRAFT_SLACK_LEN="text=2M,tls=0"`. Valid regions are [`REGIONS`];
/// unset/empty means all defaults, an unlisted region keeps its default,
/// and any typo (unknown region, malformed pair, bare number, duplicate
/// region, empty value) is a hard error — never a silent fallback to a
/// default that's the wrong size for the overlay. Same house policy as
/// `GRAFT_DEBUG`: refuse to guess.
pub const ENV: &str = "GRAFT_SLACK_LEN";

/// Region names accepted in a `GRAFT_SLACK_LEN` pair. Order is the order
/// listed in error messages (also the natural section order).
pub const REGIONS: &[&str] = &["text", "rodata", "data", "tls"];

#[derive(Debug, Clone, Copy)]
pub struct SlackParams {
    pub text_len: u32,
    pub rodata_len: u32,
    pub data_len: u32,
    pub tls_len: u32,
}

impl SlackParams {
    /// Per-region defaults, before any `GRAFT_SLACK_LEN` override.
    /// Arch-dependent only in the TLS region (`default_tls_len`).
    fn defaults(architecture: Architecture) -> Self {
        Self {
            text_len: DEFAULT_TEXT_LEN,
            rodata_len: DEFAULT_RODATA_LEN,
            data_len: DEFAULT_DATA_LEN,
            tls_len: default_tls_len(architecture),
        }
    }

    pub fn from_env(architecture: Architecture) -> Result<Self> {
        let Some(raw) = std::env::var_os(ENV) else { return Ok(Self::defaults(architecture)) };
        let s = raw
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{ENV}: value is not valid UTF-8"))?;
        Self::parse(s, architecture)
    }

    /// Parse a `GRAFT_SLACK_LEN` value into params, applying each
    /// `region=len` pair on top of the per-region defaults. See [`ENV`].
    fn parse(raw: &str, architecture: Architecture) -> Result<Self> {
        let mut params = Self::defaults(architecture);
        let mut seen: Vec<&str> = Vec::new();
        for tok in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let Some((region, value)) = tok.split_once('=') else {
                bail!(
                    "{ENV}: pair {tok:?} has no `=` — name the region explicitly, \
                     e.g. `text={tok}` (valid regions: {}). Refusing to guess which \
                     region a bare number means.",
                    REGIONS.join(", ")
                );
            };
            let region = region.trim();
            if !REGIONS.contains(&region) {
                bail!(
                    "{ENV}: unknown region {region:?} (valid: {}). Refusing to guess.",
                    REGIONS.join(", ")
                );
            }
            if seen.contains(&region) {
                bail!("{ENV}: region {region:?} set more than once");
            }
            seen.push(region);
            let len = parse_len(region, value.trim())?;
            match region {
                "text" => params.text_len = len,
                "rodata" => params.rodata_len = len,
                "data" => params.data_len = len,
                "tls" => params.tls_len = len,
                _ => unreachable!("region validated against REGIONS above"),
            }
        }
        Ok(params)
    }
}

/// Parse one region's length. Accepts a decimal or `0x`-prefixed hex
/// number, with an optional case-insensitive `K` (×1024) or `M`
/// (×1048576) suffix — the compound `region=len` syntax invites those.
/// An empty value, non-numeric digits, a lone unit suffix, or a value
/// past `u32::MAX` are all hard errors naming the region.
fn parse_len(region: &str, s: &str) -> Result<u32> {
    if s.is_empty() {
        bail!("{ENV}: region {region:?} has an empty value — give it a length, e.g. `{region}=64K`");
    }
    let (num, mult): (&str, u64) = match s.as_bytes()[s.len() - 1] {
        b'k' | b'K' => (&s[..s.len() - 1], 1024),
        b'm' | b'M' => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    if num.is_empty() {
        bail!("{ENV}: region {region:?} value {s:?} is a unit suffix with no number");
    }
    let base = if let Some(hex) = num.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        num.parse::<u64>()
    }
    .map_err(|e| anyhow::anyhow!("{ENV}: region {region:?} value {s:?} is not a valid number ({e})"))?;
    base.checked_mul(mult)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("{ENV}: region {region:?} value {s:?} overflows u32"))
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
    //
    // ZERO-filled, unlike text/rodata (0xFF for NOR-flash delta
    // friendliness): re-emitted `.bss` sections are placed in this
    // region too, and NOBITS content gets no splice write — the
    // slack's own bytes ARE the statics' initial values, which must
    // read zero.
    let data_id = obj.add_section(
        Vec::new(),
        b".data.graft_slack".to_vec(),
        SectionKind::Data,
    );
    obj.set_section_data(data_id, vec![0u8; params.data_len as usize], 4);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<SlackParams> {
        SlackParams::parse(raw, Architecture::X86_64)
    }

    #[test]
    fn xtensa_defaults_tls_to_zero() {
        let p = SlackParams::parse("", Architecture::Xtensa).unwrap();
        assert_eq!(p.tls_len, 0);
        // The other regions keep the shared defaults.
        assert_eq!(p.text_len, DEFAULT_TEXT_LEN);
        // And an explicit override still wins over the arch default.
        let p = SlackParams::parse("tls=64", Architecture::Xtensa).unwrap();
        assert_eq!(p.tls_len, 64);
    }

    #[test]
    fn empty_and_whitespace_keep_all_defaults() {
        for raw in ["", "   ", ",", " , ,"] {
            let p = parse(raw).unwrap();
            assert_eq!(p.text_len, DEFAULT_TEXT_LEN);
            assert_eq!(p.rodata_len, DEFAULT_RODATA_LEN);
            assert_eq!(p.data_len, DEFAULT_DATA_LEN);
            assert_eq!(p.tls_len, DEFAULT_TLS_LEN);
        }
    }

    #[test]
    fn unspecified_regions_keep_their_defaults() {
        let p = parse("text=123").unwrap();
        assert_eq!(p.text_len, 123);
        assert_eq!(p.rodata_len, DEFAULT_RODATA_LEN);
        assert_eq!(p.data_len, DEFAULT_DATA_LEN);
        assert_eq!(p.tls_len, DEFAULT_TLS_LEN);
    }

    #[test]
    fn multiple_regions_and_surrounding_whitespace() {
        let p = parse(" text = 2M , tls = 0 , data=0x1000 ").unwrap();
        assert_eq!(p.text_len, 2 * 1024 * 1024);
        assert_eq!(p.tls_len, 0);
        assert_eq!(p.data_len, 0x1000);
        assert_eq!(p.rodata_len, DEFAULT_RODATA_LEN);
    }

    #[test]
    fn numeric_formats_and_suffixes() {
        assert_eq!(parse("text=0").unwrap().text_len, 0);
        assert_eq!(parse("text=64").unwrap().text_len, 64);
        assert_eq!(parse("text=0xff").unwrap().text_len, 0xff);
        assert_eq!(parse("text=1k").unwrap().text_len, 1024);
        assert_eq!(parse("text=1K").unwrap().text_len, 1024);
        assert_eq!(parse("text=2m").unwrap().text_len, 2 * 1024 * 1024);
        assert_eq!(parse("text=2M").unwrap().text_len, 2 * 1024 * 1024);
        // hex with a suffix
        assert_eq!(parse("text=0x10K").unwrap().text_len, 16 * 1024);
    }

    #[test]
    fn unknown_region_is_hard_error() {
        let e = parse("txt=1").unwrap_err().to_string();
        assert!(e.contains("unknown region"), "{e}");
        assert!(e.contains("text, rodata, data, tls"), "{e}");
    }

    #[test]
    fn bare_number_without_region_is_rejected() {
        let e = parse("0").unwrap_err().to_string();
        assert!(e.contains("no `=`"), "{e}");
        assert!(e.contains("name the region explicitly"), "{e}");
    }

    #[test]
    fn empty_value_is_parse_error() {
        let e = parse("tls=").unwrap_err().to_string();
        assert!(e.contains("empty value"), "{e}");
    }

    #[test]
    fn lone_suffix_is_parse_error() {
        let e = parse("text=K").unwrap_err().to_string();
        assert!(e.contains("unit suffix with no number"), "{e}");
    }

    #[test]
    fn non_numeric_is_parse_error() {
        assert!(parse("text=abc").is_err());
        assert!(parse("text=12x").is_err());
    }

    #[test]
    fn overflow_past_u32_is_error() {
        // 4096 M = 4 GiB > u32::MAX.
        let e = parse("text=4096M").unwrap_err().to_string();
        assert!(e.contains("overflows u32"), "{e}");
        // and a bare number past u32 too
        assert!(parse("text=5000000000").is_err());
    }

    #[test]
    fn duplicate_region_is_hard_error() {
        let e = parse("text=1,text=2").unwrap_err().to_string();
        assert!(e.contains("set more than once"), "{e}");
    }
}
