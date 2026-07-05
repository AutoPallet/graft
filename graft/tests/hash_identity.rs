//! Adversarial pins for the trans_hash identity contract:
//! **equal trans_hash must imply interchangeable bytes.**
//!
//! Each test constructs the smallest object graph that would violate
//! the contract if a specific information channel were missing from
//! the hash. These exist because #42 proved "the feature works" tests
//! don't defend invariants — only counterexample attempts do. When
//! adding a resolution or identity mechanism, add the attack here.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::PathBuf;

use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolKind,
    write::{Object as WObject, Relocation as WRelocation, Symbol as WSymbol, SymbolSection},
};

fn call_ret() -> Vec<u8> {
    // call rel32 <target>; ret — reloc at +1.
    vec![0xe8, 0, 0, 0, 0, 0xc3]
}

fn global_text_symbol(
    obj: &mut WObject,
    name: &str,
    sec: object::write::SectionId,
    value: u64,
) -> object::write::SymbolId {
    obj.add_symbol(WSymbol {
        name: name.as_bytes().to_vec(),
        value,
        size: 0,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(sec),
        flags: object::write::SymbolFlags::None,
    })
}

fn scan_one(obj: WObject, entry: &str) -> graft::scan::ScanResult {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attack.o");
    std::fs::write(&path, obj.write().unwrap()).unwrap();
    graft::scan::run(&[path], &[] as &[PathBuf], &[], &[], Some(entry)).unwrap()
}

fn th(scan: &graft::scan::ScanResult, name: &str) -> [u8; 16] {
    let (nid, _) = scan
        .graph
        .symbols
        .resolve_global(name)
        .unwrap_or_else(|| panic!("{name} not in symbol index"));
    scan.trans_hash[nid as usize]
}

/// Symbol-offset attack: two byte-identical callers reference two
/// different symbols — at offset 0 and offset 8 — of ONE multi-symbol
/// target section (the gcc/esp-idf shape: several functions per
/// `.text` section). If the canonicalized reloc drops the symbol's
/// st_value, the callers hash identical while calling different code.
#[test]
fn callers_of_different_offsets_in_one_section_do_not_collide() {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    // Target: one section, two functions (mov eax,1;ret at +0,
    // mov eax,2;ret at +8).
    let tsec = obj.add_section(Vec::new(), b".text.multi".to_vec(), SectionKind::Text);
    let mut tbytes = vec![0xb8, 1, 0, 0, 0, 0xc3, 0x90, 0x90];
    tbytes.extend_from_slice(&[0xb8, 2, 0, 0, 0, 0xc3]);
    obj.section_mut(tsec).set_data(tbytes, 16);
    let f_lo = global_text_symbol(&mut obj, "f_lo", tsec, 0);
    let f_hi = global_text_symbol(&mut obj, "f_hi", tsec, 8);

    // Byte-identical callers, one per target symbol.
    for (name, target) in [("call_lo", f_lo), ("call_hi", f_hi)] {
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.{name}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(call_ret(), 16);
        global_text_symbol(&mut obj, name, sec, 0);
        obj.add_relocation(
            sec,
            WRelocation {
                offset: 1,
                symbol: target,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }

    // main references both callers.
    let msec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    let mut code = Vec::new();
    code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    code.push(0xc3);
    obj.section_mut(msec).set_data(code, 16);
    global_text_symbol(&mut obj, "main", msec, 0);
    // Symbols were already added; look them up again by re-adding
    // relocations against fresh undefined refs is wrong — reuse the
    // defined ids via a second pass instead.
    let call_lo_sym = obj.symbol_id(b"call_lo").unwrap();
    let call_hi_sym = obj.symbol_id(b"call_hi").unwrap();
    for (off, sym) in [(1u64, call_lo_sym), (6u64, call_hi_sym)] {
        obj.add_relocation(
            msec,
            WRelocation {
                offset: off,
                symbol: sym,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }

    let scan = scan_one(obj, "main");
    assert_ne!(
        th(&scan, "call_lo"),
        th(&scan, "call_hi"),
        "byte-identical callers of different offsets in one target \
         section must not share a trans_hash (st_value lost in \
         canonicalization?)"
    );
}

/// Wiring-swap attack: P references (X, Y) and Q references (Y, X) —
/// same reloc offsets, byte-identical X/Y wrappers whose *transitive*
/// content differs (distinct leaves). A hash that encodes a node's
/// successor SET rather than its slot-ordered wiring calls P and Q
/// equal; they are not (P's first call reaches leaf 1, Q's reaches
/// leaf 2).
#[test]
fn swapped_wiring_to_byte_identical_targets_does_not_collide() {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    // Leaves with different bytes.
    let mut leaf_syms = Vec::new();
    for (i, name) in ["leaf_1", "leaf_2"].iter().enumerate() {
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.{name}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(vec![0xb8, i as u8 + 1, 0, 0, 0, 0xc3], 16);
        leaf_syms.push(global_text_symbol(&mut obj, name, sec, 0));
    }
    // Byte-identical wrappers X → leaf_1, Y → leaf_2.
    let mut wrap_syms = Vec::new();
    for (name, leaf) in [("wx", leaf_syms[0]), ("wy", leaf_syms[1])] {
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.{name}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(call_ret(), 16);
        wrap_syms.push(global_text_symbol(&mut obj, name, sec, 0));
        obj.add_relocation(
            sec,
            WRelocation {
                offset: 1,
                symbol: leaf,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }
    // P calls (wx, wy); Q calls (wy, wx). Identical bytes.
    let two_calls = || {
        let mut c = Vec::new();
        c.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        c.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        c.push(0xc3);
        c
    };
    for (name, first, second) in [("p_fn", wrap_syms[0], wrap_syms[1]), ("q_fn", wrap_syms[1], wrap_syms[0])] {
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.{name}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(two_calls(), 16);
        global_text_symbol(&mut obj, name, sec, 0);
        for (off, sym) in [(1u64, first), (6u64, second)] {
            obj.add_relocation(
                sec,
                WRelocation {
                    offset: off,
                    symbol: sym,
                    addend: -4,
                    flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
                },
            )
            .unwrap();
        }
    }
    // main calls p_fn and q_fn.
    let msec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    obj.section_mut(msec).set_data(two_calls(), 16);
    global_text_symbol(&mut obj, "main", msec, 0);
    let p = obj.symbol_id(b"p_fn").unwrap();
    let q = obj.symbol_id(b"q_fn").unwrap();
    for (off, sym) in [(1u64, p), (6u64, q)] {
        obj.add_relocation(
            msec,
            WRelocation {
                offset: off,
                symbol: sym,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }

    let scan = scan_one(obj, "main");
    assert_ne!(
        th(&scan, "p_fn"),
        th(&scan, "q_fn"),
        "slot-swapped wiring to byte-identical targets must not collide"
    );
    // And the wrappers themselves differ (transitively different).
    assert_ne!(th(&scan, "wx"), th(&scan, "wy"));
}
