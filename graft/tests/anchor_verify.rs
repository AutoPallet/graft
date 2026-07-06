//! Adversarial pin for the overlay-side anchor byte-check
//! (`GRAFT_ANCHOR_VERIFY`, `anchor_verify::run`).
//!
//! Channel-2 positional resolution binds an overlay reloc into base by
//! `trans_hash` alone — no byte comparison. If base.elf is corrupt/stale
//! or a hash lies, the overlay would silently bind to wrong bytes. This
//! test corrupts the placed bytes of an anchored-target section in a
//! synthetic base image WITHOUT touching the section table (the `Placed`
//! record graft trusts) and proves:
//!   - with the check ON, the overlay refuses with the anchor-verify
//!     message (the feature is load-bearing);
//!   - with the check OFF (`GRAFT_ANCHOR_VERIFY=0`), the same corrupt
//!     base passes — i.e. the *old* behavior was a silent bind. That is
//!     the "fails-before" evidence: OFF == pre-feature.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use graft::graph::NodeId;
use graft::metadata::Placed;
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SectionKind, SymbolFlags, SymbolKind,
    write::{Object as WObject, Relocation, Symbol, SymbolScope, SymbolSection},
};

const TARGET_ADDR: u64 = 0x40_1000;
const TARGET_NAME: &str = ".text.target";

/// The distinctive bytes we place both in the overlay input's
/// `.text.target` and (identically, unless corrupted) in base at
/// `TARGET_ADDR`. No relocations, so the masked compare is exact.
fn target_bytes() -> Vec<u8> {
    (0..16u8).map(|i| 0xa0 ^ i).collect()
}

/// Overlay input object: `.text.main` (entry, PC32-refs `target`) and
/// `.text.target` (defines `target`, holds `target_bytes()`).
fn overlay_obj() -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let target_id = obj.add_section(Vec::new(), TARGET_NAME.as_bytes().to_vec(), SectionKind::Text);
    obj.set_section_data(target_id, target_bytes(), 4);
    let target = obj.add_symbol(Symbol {
        name: b"target".to_vec(),
        value: 0,
        size: target_bytes().len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(target_id),
        flags: SymbolFlags::None,
    });

    let main_id = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    // call rel32 target ; ret
    obj.set_section_data(main_id, vec![0xe8, 0, 0, 0, 0, 0xc3], 4);
    obj.add_symbol(Symbol {
        name: b"main".to_vec(),
        value: 0,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(main_id),
        flags: SymbolFlags::None,
    });
    obj.add_relocation(
        main_id,
        Relocation {
            offset: 1,
            symbol: target,
            addend: -4,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Relative,
                encoding: RelocationEncoding::Generic,
                size: 32,
            },
        },
    )
    .expect("add reloc");

    obj.write().expect("emit overlay obj")
}

/// A minimal linked ELF64 executable whose only allocated section is
/// `TARGET_NAME` at `TARGET_ADDR` holding `bytes`. `LinkedImage` reads
/// section headers (sh_addr / sh_offset / sh_size), so no program headers
/// are needed.
fn base_image(bytes: &[u8]) -> Vec<u8> {
    fn u16(o: &mut Vec<u8>, v: u16) {
        o.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(o: &mut Vec<u8>, v: u32) {
        o.extend_from_slice(&v.to_le_bytes());
    }
    fn u64v(o: &mut Vec<u8>, v: u64) {
        o.extend_from_slice(&v.to_le_bytes());
    }

    // .shstrtab: "\0" + TARGET_NAME + "\0" + ".shstrtab\0"
    let mut shstr = vec![0u8];
    let name_off = shstr.len() as u32;
    shstr.extend_from_slice(TARGET_NAME.as_bytes());
    shstr.push(0);
    let shstrtab_name_off = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab");
    shstr.push(0);

    let data_off = 64u64;
    let shstr_off = data_off + bytes.len() as u64;
    let mut after = shstr_off + shstr.len() as u64;
    while !after.is_multiple_of(8) {
        after += 1;
    }
    let shoff = after;

    let mut o: Vec<u8> = Vec::new();
    // ---- ELF header (64 bytes) ----
    o.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    o.extend_from_slice(&[0u8; 8]); // EI padding
    u16(&mut o, 2); // e_type = ET_EXEC
    u16(&mut o, 0x3e); // e_machine = EM_X86_64
    u32(&mut o, 1); // e_version
    u64v(&mut o, 0); // e_entry
    u64v(&mut o, 0); // e_phoff
    u64v(&mut o, shoff); // e_shoff
    u32(&mut o, 0); // e_flags
    u16(&mut o, 64); // e_ehsize
    u16(&mut o, 0); // e_phentsize
    u16(&mut o, 0); // e_phnum
    u16(&mut o, 64); // e_shentsize
    u16(&mut o, 3); // e_shnum
    u16(&mut o, 2); // e_shstrndx
    assert_eq!(o.len(), 64);

    // ---- section data ----
    o.extend_from_slice(bytes);
    o.extend_from_slice(&shstr);
    while !(o.len() as u64).is_multiple_of(8) {
        o.push(0);
    }
    assert_eq!(o.len() as u64, shoff);

    // ---- section headers ----
    // [0] null
    o.extend_from_slice(&[0u8; 64]);
    // [1] TARGET_NAME (PROGBITS, ALLOC|EXECINSTR)
    u32(&mut o, name_off); // sh_name
    u32(&mut o, 1); // sh_type = PROGBITS
    u64v(&mut o, 0x6); // sh_flags = ALLOC|EXECINSTR
    u64v(&mut o, TARGET_ADDR); // sh_addr
    u64v(&mut o, data_off); // sh_offset
    u64v(&mut o, bytes.len() as u64); // sh_size
    u32(&mut o, 0); // sh_link
    u32(&mut o, 0); // sh_info
    u64v(&mut o, 4); // sh_addralign
    u64v(&mut o, 0); // sh_entsize
    // [2] .shstrtab (STRTAB)
    u32(&mut o, shstrtab_name_off);
    u32(&mut o, 3); // sh_type = STRTAB
    u64v(&mut o, 0); // sh_flags
    u64v(&mut o, 0); // sh_addr
    u64v(&mut o, shstr_off); // sh_offset
    u64v(&mut o, shstr.len() as u64); // sh_size
    u32(&mut o, 0);
    u32(&mut o, 0);
    u64v(&mut o, 1);
    u64v(&mut o, 0);

    o
}

struct Harness {
    scan: graft::scan::ScanResult,
    nid: NodeId,
    by_section: HashMap<[u8; 16], Placed>,
    nodes: HashSet<NodeId>,
    _dir: tempfile::TempDir,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overlay.o");
    std::fs::write(&path, overlay_obj()).unwrap();
    let scan = graft::scan::run(&[path], &[] as &[PathBuf], &[], &[], Some("main")).unwrap();

    // Find the node backing `.text.target`.
    let nid = scan
        .graph
        .nodes
        .iter()
        .enumerate()
        .find_map(|(nid, nm)| {
            let seg = nm.segments.first()?;
            let name = &scan.objects[seg.object as usize].sections[seg.section as usize].name;
            (name == TARGET_NAME).then_some(nid as NodeId)
        })
        .expect("target node present");

    let th = scan.trans_hash[nid as usize];
    let mut by_section = HashMap::new();
    by_section.insert(th, Placed { addr: TARGET_ADDR, out_size: target_bytes().len() as u64 });
    let mut nodes = HashSet::new();
    nodes.insert(nid);

    Harness { scan, nid, by_section, nodes, _dir: dir }
}

fn out_path(h: &Harness) -> PathBuf {
    h._dir.path().join("overlay.elf")
}

#[test]
fn uncorrupted_base_passes() {
    let h = harness();
    let base = base_image(&target_bytes());
    graft::anchor_verify::run(
        true,
        &h.scan,
        &h.by_section,
        &base,
        Architecture::X86_64,
        &h.nodes,
        None,
        &out_path(&h),
    )
    .expect("matching base must byte-check clean");
}

#[test]
fn corrupt_base_refuses_and_off_bypasses() {
    let h = harness();

    // Flip one non-reloc byte of base's placed copy — the section table
    // (`by_section`) is untouched, so channel-2 still anchors here.
    let mut corrupt = target_bytes();
    corrupt[7] ^= 0xff;
    let base = base_image(&corrupt);

    // Feature ON → loud refusal naming the node, symbol, and offset.
    let err = graft::anchor_verify::run(
        true,
        &h.scan,
        &h.by_section,
        &base,
        Architecture::X86_64,
        &h.nodes,
        None,
        &out_path(&h),
    )
    .expect_err("corrupt base must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("anchor-verify REFUSED"), "message: {msg}");
    assert!(msg.contains("target"), "message names the symbol: {msg}");
    assert!(msg.contains(&format!("{TARGET_ADDR:#x}")), "message names base addr: {msg}");
    assert!(msg.contains("+0x7"), "message names first differing offset: {msg}");
    assert!(msg.contains("GRAFT_ANCHOR_VERIFY=0"), "message names the bypass: {msg}");

    // Feature OFF (== pre-feature behavior) → the same corrupt base is
    // silently accepted. This is the fails-before evidence.
    graft::anchor_verify::run(
        false,
        &h.scan,
        &h.by_section,
        &base,
        Architecture::X86_64,
        &h.nodes,
        None,
        &out_path(&h),
    )
    .expect("with the check off, the corrupt bind is (unsoundly) accepted");

    let _ = h.nid;
}
