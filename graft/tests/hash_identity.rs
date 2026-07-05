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

fn scan_two(a: WObject, b: WObject, entry: &str) -> graft::scan::ScanResult {
    let dir = tempfile::tempdir().unwrap();
    let pa = dir.path().join("a.o");
    let pb = dir.path().join("b.o");
    std::fs::write(&pa, a.write().unwrap()).unwrap();
    std::fs::write(&pb, b.write().unwrap()).unwrap();
    graft::scan::run(&[pa, pb], &[] as &[PathBuf], &[], &[], Some(entry)).unwrap()
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

/// TU-blind nominal salt attack (review cycle): two C files' same-named
/// file-local `.bss` statics — distinct mutable variables — must not
/// share a trans_hash. NOBITS sections have no bytes, so the salt IS
/// the identity; without tu_id in the salt they collided (M2 aliasing
/// class: positional resolution would bind both counters to one base
/// address).
#[test]
fn same_named_bss_locals_across_tus_do_not_collide() {
    let build_tu = |file: &str, acc: &str| {
        let mut obj =
            WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        obj.add_file_symbol(file.as_bytes().to_vec());
        let bss = obj.add_section(Vec::new(), b".bss.counter".to_vec(), SectionKind::UninitializedData);
        obj.section_mut(bss).append_bss(8, 8);
        let counter = obj.add_symbol(WSymbol {
            name: b"counter".to_vec(),
            value: 0,
            size: 8,
            kind: SymbolKind::Data,
            scope: object::write::SymbolScope::Compilation, // LOCAL
            weak: false,
            section: SymbolSection::Section(bss),
            flags: object::write::SymbolFlags::None,
        });
        let csec = obj.add_section(
            Vec::new(),
            format!(".text.{acc}").into_bytes(),
            SectionKind::Text,
        );
        // lea counter(%rip), %rax ; ret
        obj.section_mut(csec)
            .set_data(vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3], 16);
        global_text_symbol(&mut obj, acc, csec, 0);
        obj.add_relocation(
            csec,
            WRelocation {
                offset: 3,
                symbol: counter,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PC32 },
            },
        )
        .unwrap();
        obj
    };
    let mut a = build_tu("aaaa.c", "acc_a");
    let b = build_tu("bbbb.c", "acc_b");
    // main in object a, calling acc_a and acc_b.
    {
        let msec = a.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        let mut code = Vec::new();
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        code.push(0xc3);
        a.section_mut(msec).set_data(code, 16);
        global_text_symbol(&mut a, "main", msec, 0);
        let acc_a = a.symbol_id(b"acc_a").unwrap();
        let acc_b = a.add_symbol(WSymbol {
            name: b"acc_b".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: object::write::SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::write::SymbolFlags::None,
        });
        for (off, sym) in [(1u64, acc_a), (6u64, acc_b)] {
            a.add_relocation(
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
    }
    let scan = scan_two(a, b, "main");
    // The two .bss twins must have distinct hashes, hence so must
    // their byte-identical accessors.
    assert_ne!(
        th(&scan, "acc_a"),
        th(&scan, "acc_b"),
        "same-named file-local .bss statics in different TUs are \
         distinct mutable variables — their accessors must not collide"
    );
}

/// Weak/weak-diverged pin (review cycle, ld-parity lens): two WEAK
/// definitions with different content and no strong override — ld
/// binds link-order-first, graft's content tiebreak can't track that,
/// so overlay mode must REFUSE (base mode only warns). Scan-level
/// check: the graph flags the referenced diverged name.
#[test]
fn weak_weak_diverged_is_flagged_for_overlay_refusal() {
    let build = |imm: u8, tag: &str| {
        let mut obj =
            WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        obj.add_file_symbol(format!("{tag}.c").into_bytes());
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.handler_{tag}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(vec![0xb8, imm, 0, 0, 0, 0xc3], 16);
        obj.add_symbol(WSymbol {
            name: b"handler".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: object::write::SymbolScope::Linkage,
            weak: true,
            section: SymbolSection::Section(sec),
            flags: object::write::SymbolFlags::None,
        });
        obj
    };
    let mut a = build(0xAA, "wa");
    let b = build(0xBB, "wb");
    {
        let msec = a.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        a.section_mut(msec).set_data(call_ret(), 16);
        global_text_symbol(&mut a, "main", msec, 0);
        let h = a.symbol_id(b"handler").unwrap();
        a.add_relocation(
            msec,
            WRelocation {
                offset: 1,
                symbol: h,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }
    let scan = scan_two(a, b, "main");
    assert_eq!(
        scan.graph.weak_diverged_referenced,
        vec!["handler".to_string()],
        "referenced weak/weak-diverged name must be flagged"
    );

    // Control: identical weak twins are the benign shape — no flag.
    let mut a2 = build(0xAA, "wa");
    let b2 = build(0xAA, "wb");
    {
        let msec = a2.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        a2.section_mut(msec).set_data(call_ret(), 16);
        global_text_symbol(&mut a2, "main", msec, 0);
        let h = a2.symbol_id(b"handler").unwrap();
        a2.add_relocation(
            msec,
            WRelocation {
                offset: 1,
                symbol: h,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }
    let scan2 = scan_two(a2, b2, "main");
    assert!(scan2.graph.weak_diverged_referenced.is_empty());
}

/// Trampoline-cut pin (task #45): callers of the entry symbol depend
/// on its (trampolined) ADDRESS, never its content — an entry edit
/// must not dirty its callers' hashes. The cut existed in edges and
/// slot streams but not in ContentResolver, so the entry's content
/// fingerprint leaked into every direct caller's member hash.
#[test]
fn entry_edit_does_not_dirty_callers() {
    let build = |imm: u8| {
        let mut obj =
            WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let esec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        obj.section_mut(esec).set_data(vec![0xb8, imm, 0, 0, 0, 0xc3], 16);
        global_text_symbol(&mut obj, "main", esec, 0);
        // A runtime-ish caller that references the entry (the shape
        // the cut exists for: crt/IRAM code calling main).
        let csec = obj.add_section(Vec::new(), b".text.rt_caller".to_vec(), SectionKind::Text);
        obj.section_mut(csec).set_data(call_ret(), 16);
        global_text_symbol(&mut obj, "rt_caller", csec, 0);
        let m = obj.symbol_id(b"main").unwrap();
        obj.add_relocation(
            csec,
            WRelocation {
                offset: 1,
                symbol: m,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
        scan_one(obj, "main")
    };
    let a = build(1);
    let b = build(2);
    assert_ne!(th(&a, "main"), th(&b, "main"), "entry's own hash must change");
    assert_eq!(
        th(&a, "rt_caller"),
        th(&b, "rt_caller"),
        "entry edit must not dirty the entry's callers (trampoline cut)"
    );
}

/// Weak+strong attack (task #44): a weak `handler` default and a
/// strong override coexist; ld binds every reference to the STRONG
/// def. The old SymbolIndex tiebroke multi-defs by content hash,
/// ignoring bind — when the weak definer won, resolution and hashing
/// tracked a body ld never binds, and editing the strong body was
/// invisible to callers' hashes (stale bind after combine).
#[test]
fn strong_def_beats_weak_for_resolution_and_hashing() {
    let build = |strong_imm: u8| {
        // Object A: weak default handler + the caller.
        let mut a = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let wsec = a.add_section(Vec::new(), b".text.handler_weak".to_vec(), SectionKind::Text);
        // NB: these exact bytes WIN the content tiebreak against both
        // strong variants below (blake3 checked offline) — the pin is
        // only a pin if the pre-fix tiebreak would pick the weak def.
        a.section_mut(wsec).set_data(vec![0xb8, 7, 0, 0, 0, 0xc3], 16);
        a.add_symbol(WSymbol {
            name: b"handler".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: object::write::SymbolScope::Linkage,
            weak: true,
            section: SymbolSection::Section(wsec),
            flags: object::write::SymbolFlags::None,
        });
        let csec = a.add_section(Vec::new(), b".text.caller".to_vec(), SectionKind::Text);
        a.section_mut(csec).set_data(call_ret(), 16);
        global_text_symbol(&mut a, "caller", csec, 0);
        let h = a.symbol_id(b"handler").unwrap();
        a.add_relocation(
            csec,
            WRelocation {
                offset: 1,
                symbol: h,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
        let msec = a.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        a.section_mut(msec).set_data(call_ret(), 16);
        global_text_symbol(&mut a, "main", msec, 0);
        let c = a.symbol_id(b"caller").unwrap();
        a.add_relocation(
            msec,
            WRelocation {
                offset: 1,
                symbol: c,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();

        // Object B: the strong override.
        let mut b = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let ssec = b.add_section(Vec::new(), b".text.handler_strong".to_vec(), SectionKind::Text);
        b.section_mut(ssec).set_data(vec![0xb8, strong_imm, 0, 0, 0, 0xc3], 16);
        global_text_symbol(&mut b, "handler", ssec, 0);

        scan_two(a, b, "main")
    };

    let scan = build(5);
    // Resolution must pick the strong definer, like ld.
    let (nid, _) = scan.graph.symbols.resolve_global("handler").unwrap();
    let seg = scan.graph.nodes[nid as usize].segments[0];
    assert_eq!(
        scan.objects[seg.object as usize].sections[seg.section as usize].name,
        ".text.handler_strong",
        "resolution must bind the strong def, like ld"
    );
    // And an edit to the STRONG body must reach the caller's hash.
    let scan2 = build(6);
    assert_ne!(
        th(&scan, "caller"),
        th(&scan2, "caller"),
        "editing the strong (ld-bound) body must change its caller's hash"
    );
}

/// Section-form string-pool attack (task #43): a PC32 reloc against a
/// SHF_MERGE|SHF_STRINGS *section symbol* with addend −4 (string at
/// pool offset 0 → negative addend, the rip-relative shape). Real
/// toolchains never emit this — GAS refuses to reduce symbols against
/// SEC_MERGE sections — but graft used to degrade it to the bare
/// section NAME (identical across objects: callers of "cat" and "dog"
/// collided, and editing the string was invisible to the hash) while
/// ALSO dropping the closure edge. Now: whole-pool fingerprint + a
/// retained pool edge.
#[test]
fn negative_addend_pool_ref_keeps_string_content_and_edge() {
    let build = |s: &str| {
        let mut obj =
            WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let pool = obj.add_section(
            Vec::new(),
            b".rodata.str1.1".to_vec(),
            SectionKind::ReadOnlyString,
        );
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0);
        obj.section_mut(pool).set_data(bytes, 1);
        let pool_sym = obj.section_symbol(pool);

        let csec = obj.add_section(Vec::new(), b".text.caller".to_vec(), SectionKind::Text);
        // lea rel32; ret — reloc at +3, addend −4 → string at offset 0.
        obj.section_mut(csec)
            .set_data(vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3], 16);
        global_text_symbol(&mut obj, "caller", csec, 0);
        obj.add_relocation(
            csec,
            WRelocation {
                offset: 3,
                symbol: pool_sym,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PC32 },
            },
        )
        .unwrap();

        let msec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        obj.section_mut(msec).set_data(call_ret(), 16);
        global_text_symbol(&mut obj, "main", msec, 0);
        let caller = obj.symbol_id(b"caller").unwrap();
        obj.add_relocation(
            msec,
            WRelocation {
                offset: 1,
                symbol: caller,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
        scan_one(obj, "main")
    };

    let cat = build("cat");
    let dog = build("dog");
    // Different referenced string ⇒ different caller hash (this is
    // simultaneously the collision pin and the change-detection pin).
    assert_ne!(
        th(&cat, "caller"),
        th(&dog, "caller"),
        "callers of different pool strings must not collide, and a \
         string edit must reach the referrer's hash"
    );
    // The closure dependency survives: the caller keeps at least one
    // edge into the pool instead of degrading to an external sentinel.
    let (nid, _) = cat.graph.symbols.resolve_global("caller").unwrap();
    assert!(
        !cat.graph.edges[nid as usize].is_empty(),
        "negative-addend pool ref must keep a pool edge"
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

/// The ICF byte-level post-check must reject a pair whose transitive
/// content differs even when the pair is byte-identical at the top —
/// and accept a genuinely interchangeable pair. This is the
/// last-line-of-defense guard for the #42 class: if trans_hash ever
/// lies again, the fold refuses instead of shipping.
#[test]
fn icf_verifier_rejects_transitively_different_pairs() {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    for (i, name) in ["leaf_1", "leaf_2"].iter().enumerate() {
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.{name}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(vec![0xb8, i as u8 + 1, 0, 0, 0, 0xc3], 16);
        global_text_symbol(&mut obj, name, sec, 0);
    }
    // Byte-identical wrappers: wx, wz → leaf_1; wy → leaf_2.
    for (name, leaf) in [("wx", "leaf_1"), ("wz", "leaf_1"), ("wy", "leaf_2")] {
        let sec = obj.add_section(
            Vec::new(),
            format!(".text.{name}").into_bytes(),
            SectionKind::Text,
        );
        obj.section_mut(sec).set_data(call_ret(), 16);
        global_text_symbol(&mut obj, name, sec, 0);
        let target = obj.symbol_id(leaf.as_bytes()).unwrap();
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
    let msec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    let mut code = Vec::new();
    for _ in 0..3 {
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    }
    code.push(0xc3);
    obj.section_mut(msec).set_data(code, 16);
    global_text_symbol(&mut obj, "main", msec, 0);
    for (off, name) in [(1u64, "wx"), (6, "wz"), (11, "wy")] {
        let sym = obj.symbol_id(name.as_bytes()).unwrap();
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
    let nid = |name: &str| scan.graph.symbols.resolve_global(name).unwrap().0;

    // Interchangeable pair passes.
    graft::icf::verify_interchangeable(&scan, &[(nid("wx"), nid("wz"))])
        .expect("byte-identical wrappers of the same leaf must verify");
    // Transitively different pair is rejected.
    let err = graft::icf::verify_interchangeable(&scan, &[(nid("wx"), nid("wy"))])
        .expect_err("wrappers of different leaves must fail the byte-level check");
    assert!(
        format!("{err:#}").contains("raw bytes differ"),
        "unexpected verifier error: {err:#}"
    );
}

/// Mid-pool symbol attack (task #46 dissection, the roborack
/// "Down\0time\0" shape): LLVM places two string constants in one pool
/// section and a named symbol points at the SECOND entry (st_value ≠ 0).
/// Another TU carries only "time\0" at offset 0. The two callers
/// reference byte-identical content and MUST collide — this is the pin
/// for `ContentResolver::rebased` (10ccafa double-counted st_value,
/// computed offset 8, missed the pool, and fell back to a TU-unique
/// name: 159 sound ICF groups split spuriously). The other direction:
/// same shape but different second entry must NOT collide.
#[test]
fn mid_pool_symbol_ref_is_positional_content() {
    let build = |pool: &[u8], symval: u64| {
        let mut obj =
            WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let psec = obj.add_section(
            Vec::new(),
            b".rodata.str1.1".to_vec(),
            SectionKind::ReadOnlyString,
        );
        obj.section_mut(psec).set_data(pool.to_vec(), 1);
        // Named data symbol into the pool (the anon.<hash>.N shape).
        let strsym = obj.add_symbol(WSymbol {
            name: b"anon_str".to_vec(),
            value: symval,
            size: (pool.len() as u64) - symval,
            kind: SymbolKind::Data,
            scope: object::write::SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(psec),
            flags: object::write::SymbolFlags::None,
        });

        let csec = obj.add_section(Vec::new(), b".text.caller".to_vec(), SectionKind::Text);
        // lea rel32; ret — reloc at +3.
        obj.section_mut(csec)
            .set_data(vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3], 16);
        global_text_symbol(&mut obj, "caller", csec, 0);
        obj.add_relocation(
            csec,
            WRelocation {
                offset: 3,
                symbol: strsym,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PC32 },
            },
        )
        .unwrap();

        let msec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
        obj.section_mut(msec).set_data(call_ret(), 16);
        global_text_symbol(&mut obj, "main", msec, 0);
        let caller = obj.symbol_id(b"caller").unwrap();
        obj.add_relocation(
            msec,
            WRelocation {
                offset: 1,
                symbol: caller,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
        scan_one(obj, "main")
    };

    let tail = build(b"Down\0time\0", 5); // symbol at entry #2, "time"
    let whole = build(b"time\0", 0); // sole entry, same bytes
    assert_eq!(
        th(&tail, "caller"),
        th(&whole, "caller"),
        "a mid-pool symbol ref denotes its entry's CONTENT: callers of \
         byte-identical strings must collide regardless of pool layout"
    );

    let other = build(b"Down\0tame\0", 5); // same layout, different string
    assert_ne!(
        th(&other, "caller"),
        th(&whole, "caller"),
        "callers of different strings must not collide even when pool \
         layout and symbol shape match"
    );
}
