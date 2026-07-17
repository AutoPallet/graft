//! Pin for the deferred-archive ambiguity refusal: graft's demand-load
//! picks the first archive in input order, but ld satisfies an undef
//! from the first archive at-or-after the point it became live — for a
//! name defined by several archives the picks can diverge, and hashing
//! a member base.elf doesn't contain makes edits to the real one
//! invisible. Until the scan models ld's position semantics, demanding
//! such a name must refuse when the candidate members differ (and must
//! NOT refuse when they're byte-identical — either pick is
//! interchangeable — or when the name is never demanded).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolKind,
    write::{Object as WObject, Relocation as WRelocation, Symbol as WSymbol, SymbolSection},
};

/// A `.o` defining global `name` in its own text section, with `imm`
/// baked into the code so two definitions can differ (or not).
fn defining_object(name: &str, imm: u8) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let sec = obj.add_section(
        Vec::new(),
        format!(".text.{name}").into_bytes(),
        SectionKind::Text,
    );
    obj.section_mut(sec)
        .set_data(vec![0xb8, imm, 0, 0, 0, 0xc3], 16); // mov eax, imm; ret
    obj.add_symbol(WSymbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 6,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(sec),
        flags: object::write::SymbolFlags::None,
    });
    obj.write().unwrap()
}

/// A `.o` whose `main` carries a strong UND reference to `target`.
fn demanding_object(target: &str) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let sec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    obj.section_mut(sec)
        .set_data(vec![0xe8, 0, 0, 0, 0, 0xc3], 16); // call rel32; ret
    obj.add_symbol(WSymbol {
        name: b"main".to_vec(),
        value: 0,
        size: 6,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(sec),
        flags: object::write::SymbolFlags::None,
    });
    let und = obj.add_symbol(WSymbol {
        name: target.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Unknown,
        scope: object::write::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Undefined,
        flags: object::write::SymbolFlags::None,
    });
    obj.add_relocation(
        sec,
        WRelocation {
            offset: 1,
            symbol: und,
            addend: -4,
            flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
        },
    )
    .unwrap();
    obj.write().unwrap()
}

/// `ar rcs` an archive (with symbol index) from one member.
fn make_archive(dir: &Path, lib: &str, member: &str, bytes: &[u8]) -> PathBuf {
    let member_path = dir.join(member);
    std::fs::write(&member_path, bytes).unwrap();
    let lib_path = dir.join(lib);
    let status = Command::new("ar")
        .arg("rcs")
        .arg(&lib_path)
        .arg(&member_path)
        .status()
        .expect("run ar");
    assert!(status.success(), "ar rcs failed");
    lib_path
}

fn scan(
    dir: &Path,
    eager: Vec<u8>,
    archives: &[PathBuf],
) -> anyhow::Result<graft::scan::ScanResult> {
    let main_o = dir.join("main.o");
    std::fs::write(&main_o, eager).unwrap();
    graft::scan::run(&[main_o], &archives.to_vec(), &[], &[], Some("main"))
}

#[test]
fn demanded_cross_archive_duplicate_with_differing_content_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(dir.path(), "liba.a", "dup_a.o", &defining_object("dup_sym", 1));
    let b = make_archive(dir.path(), "libb.a", "dup_b.o", &defining_object("dup_sym", 2));
    let msg = match scan(dir.path(), demanding_object("dup_sym"), &[a, b]) {
        Ok(_) => panic!("differing duplicate definition must refuse"),
        Err(e) => format!("{e:#}"),
    };
    assert!(msg.contains("differing content"), "unexpected error: {msg}");
}

#[test]
fn demanded_cross_archive_duplicate_with_identical_content_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(dir.path(), "liba.a", "dup_a.o", &defining_object("dup_sym", 1));
    let b = make_archive(dir.path(), "libb.a", "dup_b.o", &defining_object("dup_sym", 1));
    let r = scan(dir.path(), demanding_object("dup_sym"), &[a, b])
        .expect("byte-identical duplicates are interchangeable");
    assert!(
        r.graph.symbols.resolve_global("dup_sym").is_some(),
        "dup_sym should have been demand-loaded"
    );
}

#[test]
fn undemanded_cross_archive_duplicate_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(dir.path(), "liba.a", "dup_a.o", &defining_object("dup_sym", 1));
    let b = make_archive(dir.path(), "libb.a", "dup_b.o", &defining_object("dup_sym", 2));
    // main demands `other_sym`, which nothing defines — the collision
    // on dup_sym must not refuse a scan that never demands it.
    let r = scan(dir.path(), demanding_object("other_sym"), &[a, b])
        .expect("undemanded duplicate must not refuse");
    assert!(
        r.graph.symbols.resolve_global("dup_sym").is_none(),
        "dup_sym should not have been pulled"
    );
}
