//! Integration smoke test: run `scan::run` against the e2e/x86 fixture's
//! built rlib. Skipped if the fixture hasn't been built yet — this keeps
//! `cargo test -p graft` green on a fresh checkout.

use std::path::PathBuf;

fn deps_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../e2e/x86/target/debug/deps")
}

fn find_rlib(prefix: &str) -> Option<PathBuf> {
    let dir = deps_dir();
    if !dir.is_dir() { return None; }
    std::fs::read_dir(&dir).ok()?.filter_map(|e| e.ok()).find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_str()?.to_string();
        if name.starts_with(prefix) && name.ends_with(".rlib") {
            Some(p)
        } else {
            None
        }
    })
}

#[test]
fn scan_base_rlib() {
    let Some(rlib) = find_rlib("libbase-") else {
        eprintln!("skipping: e2e/x86 fixture not built — run `cd e2e/x86 && cargo build`");
        return;
    };

    let r = graft::scan::run(&[&rlib]).expect("scan");
    assert!(!r.inputs.is_empty(), "expected at least one .o in the rlib");
    assert_eq!(r.inputs.len(), r.objects.len());
    assert_eq!(r.graph.nodes.len(), r.graph.edges.len());
    assert_eq!(r.trans_hash.len(), r.graph.nodes.len());

    // Every TU should have a non-empty tu_name (first STT_FILE symbol).
    for (i, obj) in r.objects.iter().enumerate() {
        assert!(!obj.tu_name.is_empty(),
            "object {i} ({}) has no STT_FILE", r.inputs[i].label());
    }

    // Determinism: re-run scan on the same input, expect identical hashes.
    let r2 = graft::scan::run(&[&rlib]).expect("scan 2");
    assert_eq!(r.trans_hash, r2.trans_hash, "trans_hash not deterministic across re-scan");

    // Non-empty alloc sections should produce non-zero hashes (sentinel
    // = [0;16] is reserved for external edges).
    let nonzero: usize = r.trans_hash.iter().filter(|h| h != &&[0u8; 16]).count();
    assert!(nonzero > 0, "no non-sentinel trans_hashes computed");

    // At least one global symbol from base should be resolvable.
    let expected: &[&str] = &[
        "_ZN4base6greet",     // base::greet — likely prefix, may have trailing hash
        "_ZN4base7compute",
    ];
    let resolved: usize = expected.iter().filter(|&&e| {
        r.graph.symbols.globals_iter().any(|(name, _)| name.contains(e))
    }).count();
    assert!(resolved > 0, "expected at least one of {expected:?} in globals");

    eprintln!("scan ok: {} objects, {} nodes, {} SCCs",
        r.objects.len(), r.graph.nodes.len(), r.scc.members.len());
}
