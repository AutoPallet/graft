//! Verify `prune::prune_object` produces parsable ELF output. Uses the
//! e2e/x86 fixture's built objects; self-skips if the fixture hasn't been
//! built yet.

use std::collections::HashSet;
use std::path::PathBuf;

use graft::prune;
use graft::resolve::{RelocDisposition, RelocQuery};

fn fixture_deps() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../e2e/x86/target/debug/deps");
    p.is_dir().then_some(p)
}

fn first_rcgu_o(dir: &std::path::Path) -> Option<PathBuf> {
    std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_str()?;
        (name.ends_with(".rcgu.o") || name.ends_with(".o")).then_some(p)
    })
}

/// Shape tests don't care where external refs land — anchor them all at
/// a fixed dummy address.
fn dummy_dispose(_q: &RelocQuery<'_>) -> anyhow::Result<RelocDisposition> {
    Ok(RelocDisposition::Anchor { tls: false, vaddr: 0x1000, verify_name: None, addend: None })
}

#[test]
fn prune_keep_all_preserves_shape() {
    let Some(deps) = fixture_deps() else {
        eprintln!("skip: fixture not built");
        return;
    };
    let Some(path) = first_rcgu_o(&deps) else {
        eprintln!("skip: no .rcgu.o under fixture deps");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let src = object::File::parse(&*bytes).unwrap();
    use object::Object;
    use object::ObjectSection;

    // Keep every section 0..n-1 (object::read is 1-based, ParsedObject is 0-based).
    let mut keep: HashSet<u32> = HashSet::new();
    for sec in src.sections() {
        let idx0 = (sec.index().0 as u32).saturating_sub(1);
        keep.insert(idx0);
    }

    let result = prune::prune_object(&bytes, &keep, &dummy_dispose)
        .unwrap_or_else(|e| panic!("prune {}: {e:#}", path.display()));
    let _ = object::File::parse(&*result.bytes)
        .unwrap_or_else(|e| panic!("re-parse pruned {}: {e}", path.display()));
    assert!(result.kept_sections > 0);
}

#[test]
fn prune_keep_none_still_parses() {
    let Some(deps) = fixture_deps() else {
        eprintln!("skip: fixture not built");
        return;
    };
    let Some(path) = first_rcgu_o(&deps) else {
        eprintln!("skip: no .rcgu.o under fixture deps");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();

    // Drop every section.
    let keep: HashSet<u32> = HashSet::new();
    let result = prune::prune_object(&bytes, &keep, &dummy_dispose).unwrap_or_else(|e| {
        // If there are relocs into sections we dropped, we expect an error.
        // That's OK — just make sure we fail cleanly, not panic.
        eprintln!("(expected) keep-none errored: {e:#}");
        prune::Pruned {
            bytes: Vec::new(),
            kept_sections: 0,
            anchor_rewrites: 0,
            assumed_names: Vec::new(),
            anchors: Vec::new(),
        }
    });
    if !result.bytes.is_empty() {
        let _ = object::File::parse(&*result.bytes).unwrap();
    }
}
