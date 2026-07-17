//! On-disk schemas for base's ELF-embedded metadata sections.
//!
//! Two sections live inside base.elf (both `SHF_ALLOC=0` /
//! `SHT_PROGBITS`), together holding everything overlay mode needs:
//! `.graft.manifest` (root record) and `.graft.sections` (the
//! content-keyed section-address table). postcard-encoded for stable
//! binary layout.

use serde::{Deserialize, Serialize};

pub const GRAFT_MAGIC: [u8; 4] = *b"GRFT";
// v4: trans_hash domain gained the nominal salt for non-content-
// addressable (mutable/byte-less) sections.
// v5: edge resolution unified with reloc disposition — edges now apply
// `--wrap` renaming and the cross-TU local fallback, changing the hash
// domain again. Each bump makes stale bases fail loud.
// v6: TLS sections join the table (addresses are template vaddrs,
// PT_TLS.p_vaddr + offset) and base reserves GRAFT_TLS_SLACK inside
// its template. A v5 base has neither: TLS refs would mis-resolve and
// TLS re-emission would have nowhere to land.
// v7: SHF_MERGE sections (.rodata.cstN) split into per-entry nodes
// like string pools — changes the node set, edges, and hash domain.
// Also: GRAFT_DATA_SLACK is zero-filled (re-emitted .bss lands there
// and must read zero; a 0xFF-filled v6 data slack would silently
// corrupt overlay statics).
// v8: addresses come from the linker map, not symbol votes, and every
// entry carries the placed (post-relaxation) output size — the lazy
// relaxation walk needs it to slice base.elf's bytes. A v7 table has
// vote-recovered addresses that silently drift on relaxing targets
// and no sizes to walk with.
// v9: the trans_hash ALGORITHM was overhauled (per-SCC color
// refinement replacing member-hash mixing; st_value folded into
// canonical addends; pool-fallback / bind-precedence / aggregator-key
// / entry-cut / salt-tu_id / segment-framing fixes) — empirically a
// total re-key of the hash domain. The manifest also gains
// `hash_algo_version` so future algorithm-only changes are
// self-documenting. A hash-value change without a version bump leaves
// the stale-base guard blind (every by_section lookup misses and the
// closure silently becomes whole-program), so never skip the bump.
// v10: manifest gains `boot` — the trans_hash of the scan node
// defining the ELF-entry symbol (`_start`-class, NOT graft's
// trampoline symbol). Because edges into the trampoline symbol are
// cut, this one hash transitively covers everything reachable from
// boot EXCEPT the redirectable subtree: crt, the pre-main constructor
// walk and its `.init_array` aggregates, fini. None of that can take
// effect through an overlay (only the entry symbol is trampolined),
// so the overlay refuses when this hash moves — without it, an edited
// constructor silently keeps running base's stale copy.
// v11: manifest gains `argv_flags` — the base link argv's flag
// surface, verbatim (argv::semantic_flags; inputs / -o / -L / -l are
// excluded because the scan captures their effect by content, and
// their paths churn per build). A flag change (-Wl,--defsym, a -T
// script swap, a --wrap addition, …) alters link semantics in ways
// the content hashes can't see; before this, such a change silently
// produced an overlay against a base linked under different flags.
// Overlay refuses on mismatch, naming the flags that changed. Stored
// as the list, not a digest, precisely so the refusal can say WHICH
// flag — it's ~20 short strings in a non-ALLOC section.
// v12 also: the manifest gains `script_hashes` (content hashes of -T
// scripts — the flag surface only sees their names, so an in-place
// memory.x edit was invisible), and overlay.elf gains a
// `.graft.overlay` stamp naming the base_abi it was linked against
// (standalone `graft combine` refuses a mismatched base). GRAFT_ENTRY_SYMBOL
// drift is refused at overlay entry (env vs manifest — the trampoline
// cut is baked into the base at link time).
// v12: `.graft.sections` gains `unplaced_mutable` — trans_hashes of
// mutable/NOBITS nodes base PLACED (their key matched map records) but
// couldn't attribute to an address. The closure walk previously
// re-emitted such nodes ("re-emitting is the safe default"), which is
// unsound for mutable content: an attribution miss — unlike a content
// change — perturbs no referrer's trans_hash, so unchanged referrers
// stay Provided on base's copy while changed referrers bind the
// re-emitted one. The walk now refuses these instead (the same fork
// the pool/walk-refusal paths already refuse).
pub const SCHEMA_VERSION: u16 = 12;

/// Version of the trans_hash algorithm itself, independent of table
/// layout. Bump whenever hash VALUES change for unchanged inputs;
/// `overlay::build_base_index` checks it alongside SCHEMA_VERSION.
///
/// v2: node identity folds `sh_size` + `sh_addralign` per segment.
/// Before this, a grown NOBITS allocation (`static X: [i32;1]` →
/// `[i32;2]`: no bytes, salt keyed only on symbol names/offsets) kept
/// its trans_hash, and channel 2 anchored the re-emitted referrer's
/// writes into base's smaller slot — silent corruption of whatever ld
/// placed next. Alignment likewise: byte-identical content demanding
/// stricter alignment must not anchor to base's placement.
pub const HASH_ALGO_VERSION: u16 = 2;

pub const SECTION_MANIFEST: &str = ".graft.manifest";
pub const SECTION_SECTIONS: &str = ".graft.sections";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GraftManifest {
    pub magic: [u8; 4],
    pub version: u16,
    /// Trans_hash algorithm version (HASH_ALGO_VERSION at base link).
    pub hash_algo_version: u16,
    /// sha1, matches NT_GNU_BUILD_ID when base was linked with --build-id=sha1.
    pub base_abi: [u8; 20],
    pub entry_symbol: String,
    /// `rustc -Vv` hash — prevents cross-toolchain overlays.
    pub toolchain_stamp: String,
    /// Link-time [start, end) address range reserved for overlays.
    /// Informational — the overlay link script is authoritative.
    pub overlay_region: (u64, u64),
    /// Boot fingerprint: the ELF-entry symbol and its scan node's
    /// trans_hash (see the v10 note above). `None` when base couldn't
    /// attribute `e_entry` to a scanned symbol — the guard is then
    /// inactive (base warns loudly).
    pub boot: Option<BootFingerprint>,
    /// The base link argv's flag surface, verbatim and in order
    /// (`argv::semantic_flags` — see the v11 note above). Overlay
    /// recomputes it over its own argv and refuses on mismatch,
    /// naming the flags that differ.
    pub argv_flags: Vec<String>,
    /// Sorted blake3 hashes of every `-T`/`--script` linker script's
    /// CONTENT at base link (`argv::script_content_hashes`). The flag
    /// surface records script names; this refuses the in-place edit
    /// (memory.x PROVIDE/KEEP changes) the name can't show.
    pub script_hashes: Vec<[u8; 32]>,
}

/// Stamp attached to overlay.elf (`.graft.overlay`): which base this
/// overlay was linked against. `graft combine` refuses a base whose
/// `base_abi` differs — a standalone combine against the wrong base is
/// geometrically plausible (same slack layout family) but semantically
/// stale everywhere.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OverlayStamp {
    pub magic: [u8; 4],
    pub base_abi: [u8; 20],
}

pub const SECTION_OVERLAY_STAMP: &str = ".graft.overlay";

pub fn encode_overlay_stamp(s: &OverlayStamp) -> anyhow::Result<Vec<u8>> {
    postcard::to_allocvec(s).map_err(|e| anyhow::anyhow!("encode overlay stamp: {e}"))
}

pub fn decode_overlay_stamp(bytes: &[u8]) -> anyhow::Result<OverlayStamp> {
    postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode overlay stamp: {e}"))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BootFingerprint {
    /// Symbol name found at the linked output's `e_entry`.
    pub symbol: String,
    pub trans_hash: [u8; 16],
}

/// "Where did base place the section with this content?" record. Stored
/// in `.graft.sections` and consulted by overlay's classify + prune
/// passes.
///
/// The key is the section's **`trans_hash`** — the transitive content
/// hash of the input section (its own bytes + canonicalized relocs +
/// successors). It carries *no name* and *no symbol identity*: a node is
/// the linker's ship/diff atom (a whole section), and its `trans_hash`
/// fully determines its behavior (see `docs/14-identity-granularity.md`).
///
/// A reference resolves **positionally**: a symbol `foo` defined in a
/// section with this `trans_hash` at in-section offset `O` lives at
/// `address + O` in base. Content-match (equal `trans_hash`) guarantees
/// base's bytes — hence base's layout, hence `O` — are identical.
///
/// This dissolves the weak-duplication problem: a weak symbol emitted
/// into two coarse sections has two distinct `trans_hash`es (each folds
/// in different section-mates); base records both; whichever copy an
/// overlay resolves through is a byte-identical, interchangeable copy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SectionEntry {
    pub trans_hash: [u8; 16],
    /// Base virtual address of the section's start (offset 0).
    pub address: u64,
    /// Placed (post-relaxation) size in base. May differ from the
    /// input section's size on relaxing targets (xtensa); the lazy
    /// walk reconciles interiors against base.elf bytes of this length.
    pub out_size: u64,
}

/// Where base placed one section: the overlay-side view of a
/// `SectionEntry` (`by_section` value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    pub addr: u64,
    pub out_size: u64,
}

/// The full `.graft.sections` payload: the content→address table (one
/// representative address per `trans_hash`), plus the set of
/// `trans_hash`es base saw at **more than one distinct address**
/// (content-identical sections it did not fold, e.g. identical
/// monomorphizations under `--icf=none`). For an ambiguous hash, a named
/// reference is disambiguated to base's exact copy via the symtab
/// snapshot when the name is unique; same-name duplicates are
/// interchangeable, so the representative address in `entries` is sound.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SectionTable {
    pub entries: Vec<SectionEntry>,
    pub ambiguous: Vec<[u8; 16]>,
    /// trans_hashes of NON-content-addressable (mutable/NOBITS) nodes
    /// whose key matched linker-map records but whose placement could
    /// not be attributed (key collision, size mismatch, byte-verify
    /// drop). Base placed these somewhere — re-emitting one would fork
    /// its state between base's copy (unchanged referrers) and the
    /// overlay's (changed referrers), so the closure walk refuses
    /// instead. Nodes with NO matching map record (gc'd / newly added)
    /// are absent from this list: base has no live copy, re-emission
    /// is safe. See the v12 note above.
    pub unplaced_mutable: Vec<[u8; 16]>,
}

pub fn encode_manifest(m: &GraftManifest) -> anyhow::Result<Vec<u8>> {
    postcard::to_allocvec(m).map_err(|e| anyhow::anyhow!("encode manifest: {e}"))
}

pub fn decode_manifest(bytes: &[u8]) -> anyhow::Result<GraftManifest> {
    postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode manifest: {e}"))
}

pub fn encode_sections(table: &SectionTable) -> anyhow::Result<Vec<u8>> {
    postcard::to_allocvec(table).map_err(|e| anyhow::anyhow!("encode sections: {e}"))
}

pub fn decode_sections(bytes: &[u8]) -> anyhow::Result<SectionTable> {
    postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode sections: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let m = GraftManifest {
            magic: GRAFT_MAGIC,
            version: SCHEMA_VERSION,
            hash_algo_version: HASH_ALGO_VERSION,
            base_abi: [0x11; 20],
            entry_symbol: "main".into(),
            toolchain_stamp: "rustc-1.94.1".into(),
            overlay_region: (0x5_0000_0000, 0x5_0100_0000),
            boot: Some(BootFingerprint { symbol: "_start".into(), trans_hash: [0x22; 16] }),
            argv_flags: vec!["-m64".into(), "-Wl,--as-needed".into()],
            script_hashes: vec![[0x33; 32]],
        };
        let bytes = encode_manifest(&m).unwrap();
        let decoded = decode_manifest(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn sections_roundtrip() {
        let table = SectionTable {
            entries: vec![
                SectionEntry { trans_hash: [1; 16], address: 0x400000, out_size: 0x40 },
                SectionEntry { trans_hash: [3; 16], address: 0x401000, out_size: 0 },
            ],
            ambiguous: vec![[7; 16]],
            unplaced_mutable: vec![[9; 16]],
        };
        let bytes = encode_sections(&table).unwrap();
        let decoded = decode_sections(&bytes).unwrap();
        assert_eq!(table, decoded);
    }
}
