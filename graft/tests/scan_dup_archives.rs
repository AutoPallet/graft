//! Archive selection compared with GNU ld, including competing definitions.

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
            flags: RelocationFlags::Elf {
                r_type: object::elf::R_X86_64_PLT32,
            },
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
    graft::scan::run(&[main_o], archives, &[], &[], Some("main"))
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
                flags: RelocationFlags::Elf {
                    r_type: object::elf::R_X86_64_PLT32,
                },
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
    let a = make_archive(
        dir.path(),
        "liba.a",
        "dup_a.o",
        &defining_object("dup_sym", 1),
    );
    let b = make_archive(
        dir.path(),
        "libb.a",
        "dup_b.o",
        &defining_object("dup_sym", 2),
    );
    let r = scan(dir.path(), demanding_object("dup_sym"), &[a, b])
        .expect("eager-introduced duplicate must not refuse");
    assert!(r.graph.symbols.resolve_global("dup_sym").is_some());
}

/// A member-introduced undefined reference uses the first subsequent provider.
#[test]
fn member_introduced_duplicate_selects_first_reachable_archive() {
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
        "dup_b.o",
        &defining_object("dup_sym", 1),
    );
    let c = make_archive(
        dir.path(),
        "libc_x.a",
        "dup_c.o",
        &defining_object("dup_sym", 2),
    );
    let result = scan(
        dir.path(),
        demanding_object("pull_me"),
        &[a.clone(), b.clone(), c.clone()],
    )
    .unwrap();
    assert_selected_matches_ld(dir.path(), &result, &[a, b, c], "dup_sym", 1);
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

/// A loaded weak definition satisfies references without extracting a strong override.
#[test]
fn weak_default_does_not_extract_an_unneeded_strong_override() {
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
    let result = scan(
        dir.path(),
        demanding_object("pull_me"),
        &[a.clone(), b.clone(), c.clone()],
    )
    .unwrap();
    assert_selected_matches_ld(dir.path(), &result, &[a, b, c], "dup_sym", 1);
}

#[test]
fn demanded_cross_archive_duplicate_with_identical_content_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_archive(
        dir.path(),
        "liba.a",
        "dup_a.o",
        &defining_object("dup_sym", 1),
    );
    let b = make_archive(
        dir.path(),
        "libb.a",
        "dup_b.o",
        &defining_object("dup_sym", 1),
    );
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
    let a = make_archive(
        dir.path(),
        "liba.a",
        "dup_a.o",
        &defining_object("dup_sym", 1),
    );
    let b = make_archive(
        dir.path(),
        "libb.a",
        "dup_b.o",
        &defining_object("dup_sym", 2),
    );
    // main demands `other_sym`, which nothing defines — the collision
    // on dup_sym must not refuse a scan that never demands it.
    let r = scan(dir.path(), demanding_object("other_sym"), &[a, b])
        .expect("undemanded duplicate must not refuse");
    assert!(
        r.graph.symbols.resolve_global("dup_sym").is_none(),
        "dup_sym should not have been pulled"
    );
}

fn selected_bytes(scan: &graft::scan::ScanResult, name: &str) -> Vec<u8> {
    let (node, offset) = scan.graph.symbols.resolve_global(name).unwrap();
    let segment = &scan.graph.nodes[node as usize].segments[0];
    scan.objects[segment.object as usize].sections[segment.section as usize].bytes
        [offset as usize..offset as usize + 6]
        .to_vec()
}

fn assert_selected_matches_ld(
    dir: &Path,
    scan: &graft::scan::ScanResult,
    archives: &[PathBuf],
    name: &str,
    immediate: u8,
) {
    let args: Vec<_> = archives
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert_selected_matches_ld_args(dir, scan, &args, name, immediate);
}

fn assert_selected_matches_ld_args(
    dir: &Path,
    scan: &graft::scan::ScanResult,
    args: &[String],
    name: &str,
    immediate: u8,
) {
    use object::{Object, ObjectSection, ObjectSymbol};
    let output = dir.join("linked.o");
    let result = Command::new("ld.bfd")
        .args(["-r", "-o"])
        .arg(&output)
        .arg(dir.join("main.o"))
        .args(args)
        .output()
        .expect("run GNU ld");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(output).unwrap();
    let elf = object::File::parse(&*bytes).unwrap();
    let symbol = elf.symbols().find(|s| s.name().ok() == Some(name)).unwrap();
    let section = elf
        .section_by_index(symbol.section_index().unwrap())
        .unwrap();
    let offset = (symbol.address() - section.address()) as usize;
    let actual = &section.data().unwrap()[offset..offset + 6];
    assert_eq!(actual, &[0xb8, immediate, 0, 0, 0, 0xc3]);
    assert_eq!(selected_bytes(scan, name), actual);
}

#[test]
fn late_reference_uses_later_provider_before_group_restarts() {
    use graft::scan::ScanInput::{EndGroup, File, StartGroup};
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("main.o");
    std::fs::write(&main, demanding_object("pull_me")).unwrap();
    let early = make_archive(
        dir.path(),
        "early.a",
        "early.o",
        &defining_object("dup_sym", 1),
    );
    let middle = make_archive(
        dir.path(),
        "middle.a",
        "middle.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    let late = make_archive(
        dir.path(),
        "late.a",
        "late.o",
        &defining_object("dup_sym", 2),
    );
    for grouped in [false, true] {
        let mut inputs = vec![File(main.clone())];
        let mut args = Vec::new();
        if grouped {
            inputs.push(StartGroup);
            args.push("--start-group".into());
        }
        for path in [&early, &middle, &late] {
            inputs.push(File(path.clone()));
            args.push(path.to_string_lossy().into_owned());
        }
        if grouped {
            inputs.push(EndGroup);
            args.push("--end-group".into());
        }
        let result = graft::scan::run_ordered(&inputs, &[], &[], None).unwrap();
        assert_selected_matches_ld_args(dir.path(), &result, &args, "dup_sym", 2);
        assert!(!result.inputs.iter().any(|i| i.source_path == early));
    }
}

#[test]
fn earlier_archive_requires_an_explicit_repeat_or_group() {
    use graft::scan::ScanInput::{EndGroup, File, StartGroup};
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("main.o");
    std::fs::write(&main, demanding_object("pull_me")).unwrap();
    let early = make_archive(
        dir.path(),
        "early.a",
        "early.o",
        &defining_object("dup_sym", 1),
    );
    let late = make_archive(
        dir.path(),
        "late.a",
        "late.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    let result = graft::scan::run(
        std::slice::from_ref(&main),
        &[early.clone(), late.clone()],
        &[],
        &[],
        None,
    )
    .unwrap();
    assert!(result.graph.symbols.resolve_global("dup_sym").is_none());
    for (inputs, args) in [
        (
            vec![
                File(main.clone()),
                File(early.clone()),
                File(late.clone()),
                File(early.clone()),
            ],
            vec![
                early.display().to_string(),
                late.display().to_string(),
                early.display().to_string(),
            ],
        ),
        (
            vec![
                File(main.clone()),
                StartGroup,
                File(early.clone()),
                File(late.clone()),
                EndGroup,
            ],
            vec![
                "--start-group".into(),
                early.display().to_string(),
                late.display().to_string(),
                "--end-group".into(),
            ],
        ),
    ] {
        let result = graft::scan::run_ordered(&inputs, &[], &[], None).unwrap();
        assert_selected_matches_ld_args(dir.path(), &result, &args, "dup_sym", 1);
    }
}

#[test]
fn archive_index_order_controls_member_introduced_reference() {
    let dir = tempfile::tempdir().unwrap();
    let archive = make_archive(
        dir.path(),
        "lib.a",
        "early.o",
        &defining_object("dup_sym", 1),
    );
    make_archive(
        dir.path(),
        "lib.a",
        "middle.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    make_archive(
        dir.path(),
        "lib.a",
        "late.o",
        &defining_object("dup_sym", 2),
    );
    let result = scan(
        dir.path(),
        demanding_object("pull_me"),
        std::slice::from_ref(&archive),
    )
    .unwrap();
    assert_selected_matches_ld(dir.path(), &result, &[archive], "dup_sym", 2);
}

#[test]
fn selected_provider_changes_callers_hash_but_unused_provider_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let early = make_archive(
        dir.path(),
        "early.a",
        "early.o",
        &defining_object("dup_sym", 1),
    );
    let middle = make_archive(
        dir.path(),
        "middle.a",
        "middle.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    let late = make_archive(
        dir.path(),
        "late.a",
        "late.o",
        &defining_object("dup_sym", 2),
    );
    let hash = || {
        let result = scan(
            dir.path(),
            demanding_object("pull_me"),
            &[early.clone(), middle.clone(), late.clone()],
        )
        .unwrap();
        let (node, _) = result.graph.symbols.resolve_global("pull_me").unwrap();
        result.trans_hash[node as usize]
    };
    let before = hash();
    make_archive(
        dir.path(),
        "early.a",
        "early.o",
        &defining_object("dup_sym", 3),
    );
    assert_eq!(before, hash());
    make_archive(
        dir.path(),
        "late.a",
        "late.o",
        &defining_object("dup_sym", 4),
    );
    assert_ne!(before, hash());
}

#[test]
fn later_eager_object_does_not_retroactively_load_an_archive() {
    use graft::scan::ScanInput::File;
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("main.o");
    std::fs::write(&main, demanding_object("dup_sym")).unwrap();
    let early = make_archive(
        dir.path(),
        "early.a",
        "early.o",
        &defining_object("dup_sym", 1),
    );
    let late = make_archive(
        dir.path(),
        "late.a",
        "late.o",
        &defining_object("dup_sym", 2),
    );
    let result = graft::scan::run_ordered(
        &[File(early.clone()), File(main), File(late.clone())],
        &[],
        &[],
        None,
    )
    .unwrap();
    assert_eq!(
        selected_bytes(&result, "dup_sym"),
        vec![0xb8, 2, 0, 0, 0, 0xc3]
    );
    assert!(!result.inputs.iter().any(|i| i.source_path == early));
}

#[test]
fn forced_root_selects_provider_before_member_introduces_reference() {
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("main.o");
    std::fs::write(&main, demanding_object("pull_me")).unwrap();
    let early = make_archive(
        dir.path(),
        "early.a",
        "early.o",
        &defining_object("dup_sym", 1),
    );
    let middle = make_archive(
        dir.path(),
        "middle.a",
        "middle.o",
        &defining_and_demanding_object("pull_me", &["dup_sym"]),
    );
    let late = make_archive(
        dir.path(),
        "late.a",
        "late.o",
        &defining_object("dup_sym", 2),
    );
    let result = graft::scan::run(
        &[main],
        &[early.clone(), middle.clone(), late.clone()],
        &["dup_sym".into()],
        &[],
        None,
    )
    .unwrap();
    let args = vec![
        "-u".into(),
        "dup_sym".into(),
        early.display().to_string(),
        middle.display().to_string(),
        late.display().to_string(),
    ];
    assert_selected_matches_ld_args(dir.path(), &result, &args, "dup_sym", 1);
}

#[test]
fn weak_undefined_reference_does_not_extract_a_member() {
    use object::{Object, ObjectSymbol};
    let dir = tempfile::tempdir().unwrap();
    let mut object = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    object.add_symbol(WSymbol {
        name: b"dup_sym".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Unknown,
        scope: object::write::SymbolScope::Linkage,
        weak: true,
        section: SymbolSection::Undefined,
        flags: object::write::SymbolFlags::None,
    });
    let archive = make_archive(
        dir.path(),
        "lib.a",
        "member.o",
        &defining_object("dup_sym", 1),
    );
    let scan = scan(
        dir.path(),
        object.write().unwrap(),
        std::slice::from_ref(&archive),
    )
    .unwrap();
    assert!(scan.graph.symbols.resolve_global("dup_sym").is_none());
    let output = dir.path().join("linked.o");
    let status = Command::new("ld.bfd")
        .args(["-r", "-o"])
        .arg(&output)
        .arg(dir.path().join("main.o"))
        .arg(archive)
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = std::fs::read(output).unwrap();
    let elf = object::File::parse(&*bytes).unwrap();
    assert!(
        !elf.symbols()
            .any(|s| s.name().ok() == Some("dup_sym") && s.is_definition())
    );
}

#[test]
fn rejects_unmatched_group_delimiters() {
    use graft::scan::ScanInput::{EndGroup, StartGroup};
    assert!(graft::scan::run_ordered(&[StartGroup], &[], &[], None).is_err());
    assert!(graft::scan::run_ordered(&[EndGroup], &[], &[], None).is_err());
}
