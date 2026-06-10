//! Nominal identity for non-content-addressable sections.
//!
//! `.bss` / zero-init `.data` sections are byte-degenerate: every one of
//! them hashes the same on content alone, so content-keyed positional
//! resolution would alias distinct mutable variables onto one base
//! address (the M2 xtensa call-to-0: `TICK_COUNTER`, `ATOMIC_TICK`, and
//! `esp_println`'s `TIMED_OUT` all bound to base's empty `.data.wifi`,
//! and `esp_println::LOCK` aliased `ESP_HAL_LOCK`). `hash::compute`
//! therefore salts such sections' leaf hashes with their sorted
//! (symbol, offset) pairs — names are the identity exactly where
//! content can't be, mirroring ld (which never content-folds writable
//! sections). See `docs/14-identity-granularity.md`.

use graft::elf::{ParsedObject, SectionInfo, SectionKind, SymbolBind, SymbolInfo};
use graft::{graph, hash};
use object::elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};

fn obj_with_sections(sections: Vec<SectionInfo>, symbols: Vec<SymbolInfo>) -> ParsedObject {
    ParsedObject {
        tu_id: [1u8; 8],
        tu_name: "test.o".into(),
        sections,
        symbols,
    }
}

fn bss_section(name: &str) -> SectionInfo {
    SectionInfo {
        name: name.into(),
        kind: SectionKind::Bss,
        alloc: true,
        sh_flags: u64::from(SHF_ALLOC | SHF_WRITE),
        bytes: Vec::new(), // NOBITS: no bytes
        relocs: Vec::new(),
    }
}

fn rodata_section(name: &str, bytes: &[u8]) -> SectionInfo {
    SectionInfo {
        name: name.into(),
        kind: SectionKind::Rodata,
        alloc: true,
        sh_flags: u64::from(SHF_ALLOC),
        bytes: bytes.to_vec(),
        relocs: Vec::new(),
    }
}

fn defining_symbol(name: &str, section: usize, value: u64) -> SymbolInfo {
    SymbolInfo {
        name: name.into(),
        bind: SymbolBind::Local,
        kind: object::SymbolKind::Data,
        defining_section: Some(section),
        size: 4,
        value,
    }
}

fn trans_hashes(obj: ParsedObject) -> Vec<hash::TransHash> {
    let objects = vec![obj];
    let g = graph::build(&objects, None);
    let scc = graph::tarjan_scc(&g);
    hash::compute(&objects, &g, &scc)
}

#[test]
fn distinct_bss_statics_get_distinct_trans_hashes() {
    // Two NOBITS sections, both byte-less, defining different statics.
    // Without the nominal salt these collapse to one trans_hash and
    // positional resolution aliases the variables.
    let obj = obj_with_sections(
        vec![bss_section(".bss.TICK"), bss_section(".bss.ATOMIC")],
        vec![defining_symbol("TICK", 0, 0), defining_symbol("ATOMIC", 1, 0)],
    );
    let ths = trans_hashes(obj);
    assert_eq!(ths.len(), 2);
    assert_ne!(ths[0], ths[1], "distinct mutable statics must not share an identity");
}

#[test]
fn same_named_bss_static_hashes_stably() {
    // The same logical static in two scans → identical trans_hash
    // (the salt is deterministic: sorted (name, value) pairs).
    let mk = || {
        obj_with_sections(
            vec![bss_section(".bss.TICK")],
            vec![defining_symbol("TICK", 0, 0)],
        )
    };
    assert_eq!(trans_hashes(mk()), trans_hashes(mk()));
}

#[test]
fn llvm_suffix_does_not_churn_mutable_identity() {
    // CGU repartitioning renames internal-linkage statics with a
    // `.llvm.<id>` suffix. The salt strips it so an otherwise-unchanged
    // static keeps its identity (re-emitting it would silently
    // *duplicate* its state into the overlay).
    let a = obj_with_sections(
        vec![bss_section(".bss.COUNTER")],
        vec![defining_symbol("COUNTER.llvm.123456789", 0, 0)],
    );
    let b = obj_with_sections(
        vec![bss_section(".bss.COUNTER")],
        vec![defining_symbol("COUNTER.llvm.987654321", 0, 0)],
    );
    assert_eq!(trans_hashes(a), trans_hashes(b));
}

#[test]
fn readonly_content_identity_is_unchanged_by_names() {
    // Read-only sections keep pure content identity: same bytes,
    // different defined-symbol names → same trans_hash (this is what
    // lets ld-style content dedup work across renames).
    let a = obj_with_sections(
        vec![rodata_section(".rodata.x", b"\x01\x02\x03\x04")],
        vec![defining_symbol("X", 0, 0)],
    );
    let b = obj_with_sections(
        vec![rodata_section(".rodata.y", b"\x01\x02\x03\x04")],
        vec![defining_symbol("Y", 0, 0)],
    );
    assert_eq!(
        trans_hashes(a),
        trans_hashes(b),
        "read-only identity must remain purely content-keyed"
    );
}

#[test]
fn scc_members_get_distinct_trans_hashes() {
    // Two sections referencing each other form one SCC. On xtensa this
    // shape is unavoidable (code l32r's into its literal pool; the pool
    // holds addresses of handlers back in the code), and base places
    // the two sections at different addresses. If SCC members shared
    // one trans_hash, `by_section[th]` would be ill-defined — the M2
    // bug that resolved `ram_resident_step` into the middle of the
    // literal pool. Each member's hash must mix in its own content.
    use graft::elf::CanonicalReloc;
    let mk_text = |name: &str, bytes: &[u8], target: &str| SectionInfo {
        name: name.into(),
        kind: SectionKind::Text,
        alloc: true,
        sh_flags: u64::from(SHF_ALLOC | SHF_EXECINSTR),
        bytes: bytes.to_vec(),
        relocs: vec![CanonicalReloc {
            offset: 0,
            target: format!("<section:{target}>"),
            r_type: 1,
            addend: 0,
        }],
    };
    let obj = obj_with_sections(
        vec![
            mk_text(".text.code", &[0x90, 0x90, 0x90, 0x90], ".text.pool"),
            mk_text(".text.pool", &[0x00, 0x00, 0x00, 0x00], ".text.code"),
        ],
        vec![],
    );
    let objects = vec![obj];
    let g = graph::build(&objects, None);
    let scc = graph::tarjan_scc(&g);
    assert_eq!(
        scc.members.len(),
        1,
        "the two sections must form one SCC for this test to mean anything"
    );
    let ths = hash::compute(&objects, &g, &scc);
    assert_ne!(
        ths[0], ths[1],
        "SCC members are distinct sections at distinct addresses — they \
         must not collapse onto one trans_hash"
    );
}

#[test]
fn ram_resident_code_stays_content_addressable() {
    // `.rwtext`-style sections (exec, possibly in a writable segment)
    // are immutable *content* — the predicate must keep them
    // content-addressable so IRAM catch-alls resolve positionally.
    let sec = SectionInfo {
        name: ".rwtext".into(),
        kind: SectionKind::Text,
        alloc: true,
        sh_flags: u64::from(SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR),
        bytes: vec![0x90; 16],
        relocs: Vec::new(),
    };
    assert!(sec.content_addressable());
    assert!(!bss_section(".bss.x").content_addressable());
    assert!(rodata_section(".rodata.c", b"hi").content_addressable());
    // Zero-size sections are byte-degenerate too.
    assert!(!rodata_section(".rodata.empty", b"").content_addressable());
}
