//! Overlay mode: re-link, pruned against a prior base build.
//!
//! Pipeline (per doc 06 § "Overlay mode"):
//!   1. Parse argv                       (argv::parse)
//!   2. Load base metadata               (from `GRAFT_BASE_ELF`)
//!   3. Hash + graph overlay's inputs    (scan::run)
//!   4. Compute closure                  (reachability walk from `main`,
//!                                        with per-section trans_hash
//!                                        match against base.symhash)
//!   5. Prune each input `.o`            (separate `prune` module)
//!   6. Generate base_symbols.ld         (PROVIDE entries for hits)
//!   7. Exec real linker                 (with pruned .o's + scripts)
//!   8. Package                          (M0.5: just write overlay.elf)
//!
//! This file does 1–4 + 6; pruning lives in `prune.rs`; step 7 shells
//! out to `ld`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};

use crate::argv;
use crate::elf::SymbolBind;
use crate::elf_attach;
use crate::graph::NodeId;
use crate::hash::TransHash;
use crate::metadata::{
    self, GraftManifest, SCHEMA_VERSION, SECTION_MANIFEST, SECTION_SYMHASH, SymHashEntry,
};
use crate::scan::{self, ScanResult};

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft overlay: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    let t_start = std::time::Instant::now();

    let link_args = argv::parse(&argv);
    let output = link_args
        .output
        .clone()
        .ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let base_path: PathBuf = std::env::var("GRAFT_BASE_ELF")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("GRAFT_BASE_ELF not set"))?;
    let base = load_base_metadata(&base_path)?;

    let scan_inputs: Vec<PathBuf> = link_args.inputs.clone();
    let scan = scan::run(&scan_inputs).context("overlay pre-scan")?;

    let closure = compute_closure(&scan, &base)?;

    let summary = format!(
        "graft overlay: base {} symhash entries · overlay {} objects / {} sections · \
         closure {} sections · provides {} globals / {} locals · scan {:.1?}\n",
        base.symhash_by_name.len(),
        scan.objects.len(),
        scan.graph.nodes.len(),
        closure.closure.len(),
        closure.provide_globals.len(),
        closure.provide_locals.len(),
        t_start.elapsed(),
    );
    eprint!("{summary}");

    // Cargo swallows a successful linker's stderr, so optionally mirror
    // to a file. `$GRAFT_LOG=path` turns it on.
    if let Ok(p) = std::env::var("GRAFT_LOG") {
        let _ = std::fs::write(&p, {
            let mut body = summary.into_bytes();
            body.extend_from_slice(&format_closure_dump(&scan, &closure));
            body
        });
    }

    // M0.5.d intermediate checkpoint: we stop here and write a marker
    // file so cargo sees a successful build. Pruning + real link land
    // in the next commit.
    std::fs::write(&output, b"graft-overlay-stub\n")
        .with_context(|| format!("write stub {}", output.display()))?;

    Ok(())
}

pub(crate) struct BaseMetadata {
    pub manifest: GraftManifest,
    /// `name` → entry. One per globally-visible symbol live in base's .symtab.
    pub symhash_by_name: HashMap<String, SymHashEntry>,
    /// `(name, tu_id)` → entry. For STB_LOCAL entries.
    pub symhash_by_local: HashMap<(String, [u8; 8]), SymHashEntry>,
}

fn load_base_metadata(path: &std::path::Path) -> Result<BaseMetadata> {
    let bytes = std::fs::read(path).with_context(|| format!("read base {}", path.display()))?;
    let manifest_bytes = elf_attach::read_section(&bytes, SECTION_MANIFEST)?
        .ok_or_else(|| anyhow!("{}: no {}", path.display(), SECTION_MANIFEST))?;
    let symhash_bytes = elf_attach::read_section(&bytes, SECTION_SYMHASH)?
        .ok_or_else(|| anyhow!("{}: no {}", path.display(), SECTION_SYMHASH))?;

    let manifest = metadata::decode_manifest(manifest_bytes)?;
    if manifest.magic != metadata::GRAFT_MAGIC {
        bail!("{}: bad graft magic", path.display());
    }
    if manifest.version != SCHEMA_VERSION {
        bail!(
            "{}: schema version {} != {}",
            path.display(),
            manifest.version,
            SCHEMA_VERSION
        );
    }

    let entries = metadata::decode_symhash(symhash_bytes)?;
    let mut by_name: HashMap<String, SymHashEntry> = HashMap::with_capacity(entries.len());
    let mut by_local: HashMap<(String, [u8; 8]), SymHashEntry> = HashMap::new();
    for e in entries {
        match e.tu {
            None => {
                by_name.insert(e.name.clone(), e);
            }
            Some(tu) => {
                by_local.insert((e.name.clone(), tu), e);
            }
        }
    }
    Ok(BaseMetadata {
        manifest,
        symhash_by_name: by_name,
        symhash_by_local: by_local,
    })
}

pub(crate) struct Closure {
    /// Nodes we must include in the overlay link (their trans_hash did
    /// not match base's).
    pub closure: Vec<NodeId>,
    /// Defined globals we can satisfy from base — `(name, address, size)`.
    /// Emitted as `PROVIDE(name = 0x…);` in base_symbols.ld.
    pub provide_globals: Vec<(String, u64, u32)>,
    /// Defined locals we need to satisfy from base, renamed to
    /// `<name>@<tu_id>` when pruning.
    pub provide_locals: Vec<(String, [u8; 8], u64, u32)>,
}

fn compute_closure(scan: &ScanResult, base: &BaseMetadata) -> Result<Closure> {
    // Find entry point: the `main` symbol (or whatever's in base's
    // manifest.entry_symbol). For M0.5 x86 it's always `main`.
    let entry_name = base.manifest.entry_symbol.as_str();
    let entry_node = scan
        .graph
        .symbols
        .resolve_global(entry_name)
        .ok_or_else(|| anyhow!("entry symbol `{entry_name}` not defined in overlay inputs"))?;

    let mut closure: Vec<NodeId> = Vec::new();
    let mut provide_globals: Vec<(String, u64, u32)> = Vec::new();
    let mut provide_locals: Vec<(String, [u8; 8], u64, u32)> = Vec::new();

    // Per-node state: Unknown / Included / Provided. We don't walk into
    // nodes marked Provided — base already satisfies everything reachable
    // from them (by trans_hash).
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Decision { Unknown, Included, Provided }
    let mut decision = vec![Decision::Unknown; scan.graph.nodes.len()];

    // DFS from entry.
    let mut stack = vec![entry_node];
    while let Some(nid) = stack.pop() {
        if decision[nid as usize] != Decision::Unknown {
            continue;
        }
        match classify(nid, scan, base) {
            Classification::Provided { globals, locals } => {
                decision[nid as usize] = Decision::Provided;
                provide_globals.extend(globals);
                provide_locals.extend(locals);
            }
            Classification::Included => {
                decision[nid as usize] = Decision::Included;
                closure.push(nid);
                // Walk its reloc targets.
                for &succ in &scan.graph.edges[nid as usize] {
                    if decision[succ as usize] == Decision::Unknown {
                        stack.push(succ);
                    }
                }
            }
        }
    }

    // Sort + dedup provides so the ld script is stable.
    provide_globals.sort();
    provide_globals.dedup_by(|a, b| a.0 == b.0);
    provide_locals.sort();
    provide_locals.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    // And closure for determinism.
    closure.sort();

    Ok(Closure { closure, provide_globals, provide_locals })
}

enum Classification {
    Provided {
        globals: Vec<(String, u64, u32)>,
        locals: Vec<(String, [u8; 8], u64, u32)>,
    },
    Included,
}

/// Decide whether a section is Provided by base (any defined symbol in it
/// matches base.symhash on trans_hash) or Included in overlay's link.
fn classify(nid: NodeId, scan: &ScanResult, base: &BaseMetadata) -> Classification {
    let nm = &scan.graph.nodes[nid as usize];
    let obj = &scan.objects[nm.object as usize];
    let sec = &obj.sections[nm.section as usize];
    let th: TransHash = scan.trans_hash[nid as usize];

    // Collect defined symbols in this section.
    let mut globals: Vec<(String, u64, u32)> = Vec::new();
    let mut locals: Vec<(String, [u8; 8], u64, u32)> = Vec::new();
    let mut any_match = false;
    let mut any_defined_symbol = false;

    for &sym_idx in &sec.defined_symbols {
        let sym = &obj.symbols[sym_idx];
        if sym.name.is_empty() {
            continue;
        }
        any_defined_symbol = true;
        match sym.bind {
            SymbolBind::Global | SymbolBind::Weak => {
                if let Some(e) = base.symhash_by_name.get(&sym.name) {
                    if e.trans_hash == th {
                        any_match = true;
                        globals.push((sym.name.clone(), e.address, e.size));
                    }
                }
            }
            SymbolBind::Local => {
                if let Some(e) = base.symhash_by_local.get(&(sym.name.clone(), obj.tu_id)) {
                    if e.trans_hash == th {
                        any_match = true;
                        locals.push((sym.name.clone(), obj.tu_id, e.address, e.size));
                    }
                }
            }
        }
    }

    // A section with no defined symbols we can match can't be Provided —
    // we have no address to point at. (Examples: `.eh_frame` fragments,
    // `.rodata..Lanon.*` constants with no exported name.) Include it.
    if !any_defined_symbol || !any_match {
        return Classification::Included;
    }
    Classification::Provided { globals, locals }
}

fn format_closure_dump(scan: &ScanResult, c: &Closure) -> Vec<u8> {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "closure sections ({}):", c.closure.len());
    for &nid in &c.closure {
        let nm = &scan.graph.nodes[nid as usize];
        let obj = &scan.objects[nm.object as usize];
        let sec = &obj.sections[nm.section as usize];
        let label = scan.inputs[nm.object as usize].label();
        let _ = writeln!(s, "  [{nid}] {label} :: {} ({} bytes)", sec.name, sec.bytes.len());
    }
    let _ = writeln!(s, "provides globals ({}):", c.provide_globals.len());
    for (n, addr, sz) in &c.provide_globals {
        let _ = writeln!(s, "  {n} = {addr:#x} ({sz} bytes)");
    }
    let _ = writeln!(s, "provides locals ({}):", c.provide_locals.len());
    for (n, tu, addr, sz) in &c.provide_locals {
        let tu_hex: String = tu.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(s, "  {n}@{tu_hex} = {addr:#x} ({sz} bytes)");
    }
    s.into_bytes()
}
