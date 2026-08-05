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

/// A `.o` defining `names` in one text section, with `imm` baked into
/// the code so two definitions can differ (or not). `weak` applies to
/// every defined name.
fn defining_object_full(names: &[&str], imm: u8, weak: bool) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let sec = obj.add_section(
        Vec::new(),
        format!(".text.{}", names[0]).into_bytes(),
        SectionKind::Text,
    );
    obj.section_mut(sec)
        .set_data(vec![0xb8, imm, 0, 0, 0, 0xc3], 16); // mov eax, imm; ret
    for name in names {
        obj.add_symbol(WSymbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 6,
            kind: SymbolKind::Text,
            scope: object::write::SymbolScope::Linkage,
            weak,
            section: SymbolSection::Section(sec),
            flags: object::write::SymbolFlags::None,
        });
    }
    obj.write().unwrap()
}

fn defining_object(name: &str, imm: u8) -> Vec<u8> {
    defining_object_full(&[name], imm, false)
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

/// A `.o` defining global `name` whose code carries strong UND
/// references to each of `targets` — the shape of an archive member
/// that introduces new undefs when pulled.
fn defining_and_demanding_object(name: &str, targets: &[&str]) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let sec = obj.add_section(
        Vec::new(),
        format!(".text.{name}").into_bytes(),
        SectionKind::Text,
    );
    let mut code = Vec::new();
    for _ in targets {
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]); // call rel32
    }
    code.push(0xc3);
    obj.section_mut(sec).set_data(code, 16);
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
    for (i, target) in targets.iter().enumerate() {
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
                offset: (i * 5 + 1) as u64,
                symbol: und,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }
    obj.write().unwrap()
}

/// An undef live from position zero (eager input) is satisfied by the
/// globally-first definer in ld too — first-wins IS ld's pick, so a
/// differing cross-archive duplicate must NOT refuse there. This is
/// the esp-idf `__assert_func` shape (libnewlib.a vs toolchain
/// libc.a, preempted via `-u`), which fired the first cut of this
/// guard on every real build.
#[test]
fn eager_introduced_duplicate_pulls_first_archive() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(dir.path(), "liba.a", "dup_a.o", &defining_object("dup_sym", 1));
    let b = make_archive(dir.path(), "libb.a", "dup_b.o", &defining_object("dup_sym", 2));
    let r = scan(dir.path(), demanding_object("dup_sym"), &[a, b])
        .expect("eager-introduced duplicate must not refuse");
    assert!(r.graph.symbols.resolve_global("dup_sym").is_some());
}

/// An undef introduced by a pulled member becomes live mid-scan; ld
/// satisfies it from the first archive at-or-after that position,
/// which first-wins can't model — differing content must refuse.
#[test]
fn member_introduced_duplicate_with_differing_content_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(
        dir.path(),
        "liba.a",
        "pull.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    let b = make_archive(dir.path(), "libb.a", "dup_b.o", &defining_object("dup_sym", 1));
    let c = make_archive(dir.path(), "libc_x.a", "dup_c.o", &defining_object("dup_sym", 2));
    let msg = match scan(dir.path(), demanding_object("pull_me"), &[a, b, c]) {
        Ok(_) => panic!("member-introduced differing duplicate must refuse"),
        Err(e) => format!("{e:#}"),
    };
    assert!(msg.contains("differing content"), "unexpected error: {msg}");
}

/// The esp-idf weak-default pattern: one archive carries a WEAK
/// default, another the strong override, bytes differ. The binding
/// outcome isn't positional (strong preempts weak once both load), so
/// this proceeds — provided the strong member actually gets loaded.
#[test]
fn weak_default_with_loaded_strong_override_proceeds() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(
        dir.path(),
        "liba.a",
        "pull.o",
        &defining_and_demanding_object("pull_me", &["dup_sym", "strong_extra"]),
    );
    let b = make_archive(
        dir.path(),
        "libb.a",
        "weak.o",
        &defining_object_full(&["dup_sym"], 1, true),
    );
    // The strong override lives in a member that also defines
    // strong_extra, so it gets demand-loaded independently.
    let c = make_archive(
        dir.path(),
        "libc_x.a",
        "strong.o",
        &defining_object_full(&["dup_sym", "strong_extra"], 2, false),
    );
    let r = scan(dir.path(), demanding_object("pull_me"), &[a, b, c])
        .expect("weak default + loaded strong override must proceed");
    assert!(r.graph.symbols.resolve_global("dup_sym").is_some());
}

/// Same shape, but nothing ever demands the strong member — ld's
/// binding can't be reproduced from graft's member set, so refuse.
#[test]
fn weak_default_with_unloaded_strong_override_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(
        dir.path(),
        "liba.a",
        "pull.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    let b = make_archive(
        dir.path(),
        "libb.a",
        "weak.o",
        &defining_object_full(&["dup_sym"], 1, true),
    );
    let c = make_archive(
        dir.path(),
        "libc_x.a",
        "strong.o",
        &defining_object_full(&["dup_sym"], 2, false),
    );
    let msg = match scan(dir.path(), demanding_object("pull_me"), &[a, b, c]) {
        Ok(_) => panic!("unloaded strong override must refuse"),
        Err(e) => format!("{e:#}"),
    };
    assert!(msg.contains("never demand-loaded"), "unexpected error: {msg}");
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
