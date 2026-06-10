//! Verify `prune::prune_object` produces parsable ELF output. Uses the
//! e2e/x86 fixture's built objects; self-skips if the fixture hasn't been
//! built yet.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use graft::hash::TransHash;
use graft::prune;

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

/// Empty resolver tables — every reference is unresolvable, which is what
/// these shape tests want (keep-all has no cross-section base refs;
/// keep-none is allowed to error cleanly).
#[derive(Default)]
struct Tables {
    by_section: HashMap<TransHash, u64>,
    ambiguous_sections: HashSet<TransHash>,
    globals: HashMap<String, (TransHash, u64)>,
    locals: HashMap<(String, [u8; 8]), (TransHash, u64)>,
    locals_any_tu: HashMap<String, (TransHash, u64)>,
    wrapped: HashSet<String>,
    base_symtab: HashMap<String, u64>,
    base_symtab_ambiguous: HashSet<String>,
    closure_trans_hashes: HashSet<TransHash>,
    mutable_trans_hashes: HashSet<TransHash>,
}

impl Tables {
    fn resolver(&self) -> prune::BaseResolver<'_> {
        prune::BaseResolver {
            by_section: &self.by_section,
            ambiguous_sections: &self.ambiguous_sections,
            overlay_globals: &self.globals,
            overlay_locals: &self.locals,
            overlay_locals_any_tu: &self.locals_any_tu,
            wrapped: &self.wrapped,
            base_symtab: &self.base_symtab,
            base_symtab_ambiguous: &self.base_symtab_ambiguous,
            closure_trans_hashes: &self.closure_trans_hashes,
            mutable_trans_hashes: &self.mutable_trans_hashes,
        }
    }
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

    let t = Tables::default();
    let sec_ths: HashMap<u32, TransHash> = HashMap::new();
    let result = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &sec_ths)
        .unwrap_or_else(|e| panic!("prune {}: {e:#}", path.display()));
    // Re-parse.
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
    let t = Tables::default();
    let sec_ths: HashMap<u32, TransHash> = HashMap::new();
    let result = prune::prune_object(&bytes, [0xAB; 8], &keep, &t.resolver(), &sec_ths)
        .unwrap_or_else(|e| {
            // If there are relocs into sections we dropped, we expect an error.
            // That's OK — just make sure we fail cleanly, not panic.
            eprintln!("(expected) keep-none errored: {e:#}");
            prune::Pruned {
                bytes: Vec::new(),
                kept_sections: 0,
                abs_rewrites: 0,
                assumed_names: Vec::new(),
            }
        });
    if !result.bytes.is_empty() {
        let _ = object::File::parse(&*result.bytes).unwrap();
    }
}
