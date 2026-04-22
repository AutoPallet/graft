//! On-disk schemas for base's ELF-embedded metadata sections.
//!
//! Two sections live inside base.elf (both `SHF_ALLOC=0` /
//! `SHT_PROGBITS`), together holding everything overlay mode needs:
//! `.graft.manifest` (root record) and `.graft.symhash` (per-symbol
//! address + transitive hash). postcard-encoded for stable binary
//! layout.

use serde::{Deserialize, Serialize};

pub const GRAFT_MAGIC: [u8; 4] = *b"GRFT";
pub const SCHEMA_VERSION: u16 = 1;

pub const SECTION_MANIFEST: &str = ".graft.manifest";
pub const SECTION_SYMHASH: &str = ".graft.symhash";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GraftManifest {
    pub magic: [u8; 4],
    pub version: u16,
    /// sha1, matches NT_GNU_BUILD_ID when base was linked with --build-id=sha1.
    pub base_abi: [u8; 20],
    pub entry_symbol: String,
    /// `rustc -Vv` hash — prevents cross-toolchain overlays.
    pub toolchain_stamp: String,
    /// Link-time [start, end) address range reserved for overlays.
    /// Informational — the overlay link script is authoritative.
    pub overlay_region: (u64, u64),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SymHashEntry {
    pub name: String,
    /// `None` for STB_GLOBAL. `Some(tu_id)` for STB_LOCAL, where
    /// `tu_id = blake3(STT_FILE symbol name of defining .o)[:8]`.
    pub tu: Option<[u8; 8]>,
    /// Truncated blake3 of (bytes || canonical relocs || SCC-successor
    /// transitive hashes). Sections in the same SCC share one hash.
    /// All-zeros for externally-sourced symbols (prebuilt libs,
    /// linker-provided).
    pub trans_hash: [u8; 16],
    /// `st_value` from base's final `.symtab`.
    pub address: u64,
    /// `st_size` from base's final `.symtab`.
    pub size: u32,
}

pub fn encode_manifest(m: &GraftManifest) -> anyhow::Result<Vec<u8>> {
    postcard::to_allocvec(m).map_err(|e| anyhow::anyhow!("encode manifest: {e}"))
}

pub fn decode_manifest(bytes: &[u8]) -> anyhow::Result<GraftManifest> {
    postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode manifest: {e}"))
}

pub fn encode_symhash(entries: &[SymHashEntry]) -> anyhow::Result<Vec<u8>> {
    postcard::to_allocvec(entries).map_err(|e| anyhow::anyhow!("encode symhash: {e}"))
}

pub fn decode_symhash(bytes: &[u8]) -> anyhow::Result<Vec<SymHashEntry>> {
    postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode symhash: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let m = GraftManifest {
            magic: GRAFT_MAGIC,
            version: SCHEMA_VERSION,
            base_abi: [0x11; 20],
            entry_symbol: "main".into(),
            toolchain_stamp: "rustc-1.94.1".into(),
            overlay_region: (0x5_0000_0000, 0x5_0100_0000),
        };
        let bytes = encode_manifest(&m).unwrap();
        let decoded = decode_manifest(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn symhash_roundtrip() {
        let entries = vec![
            SymHashEntry {
                name: "main".into(),
                tu: None,
                trans_hash: [1; 16],
                address: 0x400000,
                size: 42,
            },
            SymHashEntry {
                name: "_ZN4core3fmt9Formatter...".into(),
                tu: Some([2; 8]),
                trans_hash: [3; 16],
                address: 0x401000,
                size: 128,
            },
        ];
        let bytes = encode_symhash(&entries).unwrap();
        let decoded = decode_symhash(&bytes).unwrap();
        assert_eq!(entries, decoded);
    }
}
