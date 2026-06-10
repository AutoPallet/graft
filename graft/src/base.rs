//! Base mode: the first, from-scratch link.
//!
//! Pre-scan runs in a background thread while the real linker does its
//! work on the same inputs — hashing hides under the linker's runtime.
//! After the link lands, we re-open the output ELF for `.symtab`
//! addresses, join them with the pre-scan's trans_hashes, and attach
//! `.graft.manifest` + `.graft.sections` as SHF_ALLOC=0 sections.

use std::io::Write;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use object::{Object, ObjectSymbol, SymbolScope};

use crate::argv;
use crate::elf::SymbolBind;
use crate::elf_attach::{self, NewSection};
use crate::metadata::{
    GRAFT_MAGIC, GraftManifest, SCHEMA_VERSION, SECTION_MANIFEST, SECTION_SECTIONS, SectionEntry,
    SectionTable, encode_manifest, encode_sections,
};
use crate::scan::{self, ScanResult};

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft base: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    // ldproxy (esp-idf-sys's link wrapper) can ask the real linker
    // to chdir before resolving relative archive paths via the
    // `--ldproxy-cwd <dir>` flag. Inputs in argv after that flag
    // (e.g. `esp-idf/xtensa/libxtensa.a`) are relative to that dir,
    // not to graft's cwd. Apply it here so both the pre-scan and
    // the linker invocation see the same view. ldproxy itself still
    // sees the flag in passthrough — chdir is idempotent.
    if let Some(cwd) = extract_flag(&argv, "--ldproxy-cwd") {
        std::env::set_current_dir(&cwd)
            .with_context(|| format!("chdir to --ldproxy-cwd {cwd}"))?;
    }

    let link_args = argv::parse(&argv);
    let output = link_args.output.clone().ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let t_start = std::time::Instant::now();

    // Spawn pre-scan concurrently with the real linker. Both touch the
    // same files (read-only), so there's no contention. Scan sees only
    // the user-supplied inputs — the synthetic slack `.o` (if any) is
    // pure linker-side machinery and shouldn't appear in the call graph.
    let driver = crate::argv::driver_path(&argv);
    let (eager_inputs, deferred_inputs) =
        crate::overlay::resolve_scan_inputs(&link_args, &driver);
    let extra_roots = link_args.undefined.clone();
    let wrapped = link_args.wrapped.clone();
    // The trampoline target (from GRAFT_ENTRY_SYMBOL, default `main`).
    // Threaded into the scan so the trans_hash graph cuts edges into it —
    // base and overlay must agree on this name (overlay reads it back
    // from the manifest). See `graph::build`.
    let entry_for_scan = find_entry_symbol(&[]);
    let entry_clone = entry_for_scan.clone();
    let scan_handle = std::thread::spawn(move || {
        let t = std::time::Instant::now();
        let r = scan::run(
            &eager_inputs,
            &deferred_inputs,
            &extra_roots,
            &wrapped,
            entry_clone.as_deref(),
        );
        (r, t.elapsed())
    });

    // Splice is the only overlay mode, so base always carries slack
    // regions for the overlay to splice into. Detect the target arch
    // from the inputs to mirror it into the synthetic slack `.o`.
    crate::slack::ensure_splice_mode()?;
    let arch = crate::slack::detect_architecture(&link_args.inputs)
        .context("detect target architecture from input objects")?;
    let mut argv = inject_slack(argv, arch, &output)?;

    // `-Map` oracle (GRAFT_MAP_ORACLE=1): ask the real linker for its
    // map and, after address recovery, verify every recovered section
    // address against it — ld is the reference implementation, so any
    // disagreement is an identity-model bug that must fail the base
    // build. Enabled in the e2e suites; see `mapcheck`.
    let map_oracle = std::env::var("GRAFT_MAP_ORACLE").is_ok_and(|v| !v.is_empty() && v != "0");
    let map_path = output.with_extension("graft-map");
    if map_oracle {
        argv.push(format!("-Wl,-Map={}", map_path.display()));
    }
    let argv = argv;

    let t_link_start = std::time::Instant::now();
    let ld_status = exec_real_linker(&argv)?;
    let t_link = t_link_start.elapsed();
    let (scan_result, t_scan) = scan_handle
        .join()
        .map_err(|_| anyhow!("pre-scan thread panicked"))?;
    let scan_result = scan_result.context("pre-scan failed")?;

    let t_parallel = t_start.elapsed();

    if !ld_status.success() {
        bail!("real linker exited with {}", ld_status);
    }

    let t_post = std::time::Instant::now();
    let elf_bytes = std::fs::read(&output).with_context(|| format!("read {}", output.display()))?;
    if let Ok(p) = std::env::var("GRAFT_DEBUG_DUMP_GRAPH")
        && !p.is_empty()
    {
        if let Err(e) = crate::debug_dump::dump_graph(std::path::Path::new(&p), &scan_result) {
            eprintln!("graft base: GRAFT_DEBUG_DUMP_GRAPH write {p} failed: {e}");
        }
    }
    let (table, node_addrs) = build_section_table(&scan_result, &elf_bytes)?;

    if map_oracle {
        let text = std::fs::read_to_string(&map_path)
            .with_context(|| format!("GRAFT_MAP_ORACLE: read {}", map_path.display()))?;
        let map = crate::mapcheck::parse_map(&text);
        let stats = crate::mapcheck::oracle_check(&scan_result, &node_addrs, &map)
            .context("GRAFT_MAP_ORACLE")?;
        eprintln!(
            "graft base map-oracle: {} recovered addresses verified against the \
             linker map · {} ambiguous-key skipped · {} placed-but-unrecovered",
            stats.checked, stats.skipped_ambiguous_key, stats.coverage_gaps,
        );
    }

    let manifest = GraftManifest {
        magic: GRAFT_MAGIC,
        version: SCHEMA_VERSION,
        base_abi: compute_base_abi(&elf_bytes),
        entry_symbol: entry_for_scan.clone().unwrap_or_else(|| "main".into()),
        toolchain_stamp: toolchain_stamp(),
        overlay_region: (0, 0), // M0.5 doesn't reserve one; overlay picks a disjoint addr
    };

    let manifest_bytes = encode_manifest(&manifest)?;
    let sections_bytes = encode_sections(&table)?;
    let new_elf = elf_attach::append_sections(
        &elf_bytes,
        &[
            NewSection { name: SECTION_MANIFEST, data: &manifest_bytes },
            NewSection { name: SECTION_SECTIONS, data: &sections_bytes },
        ],
    )?;

    atomic_write(&output, &new_elf)?;

    let t_total = t_start.elapsed();
    eprintln!(
        "graft base: {} objects · {} sections · {} section entries ({} ambiguous) · \
         link {:.1?} · scan {:.1?} · link+scan {:.1?} · attach {:.1?} · total {:.1?}",
        scan_result.objects.len(),
        scan_result.graph.nodes.len(),
        table.entries.len(),
        table.ambiguous.len(),
        t_link,
        t_scan,
        t_parallel,
        t_post.elapsed(),
        t_total,
    );
    Ok(())
}

/// Synthesize a slack `.o`, write it next to the output, and append
/// it (plus `--undefined=` flags so `--gc-sections` keeps it) to the
/// linker argv. Idempotent on re-link.
fn inject_slack(
    mut argv: Vec<String>,
    arch: object::Architecture,
    output: &std::path::Path,
) -> Result<Vec<String>> {
    let params = crate::slack::SlackParams::from_env()?;
    let bytes = crate::slack::synthesize(arch, &params)?;
    let slack_path = output.with_extension("graft-slack.o");
    atomic_write(&slack_path, &bytes)?;

    argv.push(slack_path.to_string_lossy().into_owned());
    argv.push(format!("-Wl,--undefined={}", crate::slack::TEXT_SYMBOL));
    argv.push(format!("-Wl,--undefined={}", crate::slack::RODATA_SYMBOL));
    argv.push(format!("-Wl,--undefined={}", crate::slack::DATA_SYMBOL));
    Ok(argv)
}

fn exec_real_linker(argv: &[String]) -> Result<std::process::ExitStatus> {
    let real = std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&real)
        .args(&argv[1..])
        .status()
        .with_context(|| format!("exec {real}"))?;
    Ok(status)
}

/// Recover each retained input section's base virtual address, keyed by
/// the section's `trans_hash`, producing the `.graft.sections` table.
///
/// base.elf's section headers only expose the *merged output* section
/// (e.g. one `.rwtext` for all CGUs), so per-input addresses are
/// recovered from symbols: for each symbol a node defines that base
/// resolved, `candidate = final_addr − st_value` is the section start.
/// Symbols genuinely in *this* copy agree on one base; a weak global ld
/// resolved to a *different* copy is an outlier, so we take the majority
/// (preferring locals — they are never cross-resolved, hence
/// authoritative). Content-identical sections base placed at distinct
/// addresses (un-folded identical monomorphizations) collide on
/// `trans_hash`; we keep one representative address and flag the hash
/// `ambiguous` so a named reference can be disambiguated by name when the
/// name is unique. See `docs/14-identity-granularity.md`.
///
/// Aggregator brackets (`__init_array_start` etc.) and other
/// linker-script / crt symbols are intentionally NOT in this table —
/// they carry no section content and resolve overlay-side through the
/// base.elf symtab snapshot (prune channel 3) with a post-link verify.
/// Returns the encoded table plus the raw per-node recovery
/// (`NodeId → placed section base`), which the `-Map` oracle checks
/// against the linker's own record — including the individual copies
/// behind an ambiguous trans_hash, which the collapsed table can't
/// represent.
fn build_section_table(
    scan: &ScanResult,
    elf_bytes: &[u8],
) -> Result<(SectionTable, std::collections::HashMap<u32, u64>)> {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;
    let elf = object::File::parse(elf_bytes).context("parse output ELF")?;

    // (name, key_tu) → unique final address, or `None` once the name is
    // seen at two distinct addresses (then it's a poor surrogate and we
    // skip it for voting). key_tu = None for globals/weaks, Some(tu) for
    // STT_FILE-partitioned locals — matching `tu_id` derivation.
    let mut final_addr: HashMap<(String, Option<[u8; 8]>), Option<u64>> = HashMap::new();
    let mut current_tu: Option<[u8; 8]> = None;
    for s in elf.symbols() {
        let name_raw = s.name().unwrap_or("");
        if matches!(s.kind(), object::SymbolKind::File) {
            current_tu = Some(tu_id_from_file_name(name_raw));
            continue;
        }
        if s.is_undefined() { continue; }
        if matches!(s.kind(), object::SymbolKind::Section) { continue; }
        if name_raw.is_empty() { continue; }
        let is_global = matches!(s.scope(), SymbolScope::Linkage | SymbolScope::Dynamic);
        let key_tu = if is_global { None } else { current_tu };
        match final_addr.entry((name_raw.to_string(), key_tu)) {
            Entry::Vacant(v) => {
                v.insert(Some(s.address()));
            }
            Entry::Occupied(mut o) => {
                if let Some(a) = *o.get()
                    && a != s.address()
                {
                    o.insert(None); // same (name, tu) at two addresses → unusable surrogate
                }
            }
        }
    }

    // (object, section) → node, keeping the first node for shared
    // sections (mirrors `node_id_of`'s first-match for string-pool
    // sub-nodes / aggregator contributors).
    let mut node_of: HashMap<(u32, u32), u32> = HashMap::new();
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        for seg in &nm.segments {
            node_of.entry((seg.object, seg.section)).or_insert(nid as u32);
        }
    }

    // Per-node candidate section-base addresses, kept separate because
    // they carry different authority: ld can resolve a *global/weak*
    // name to a different copy than this node's (cross-resolution), so
    // those are majority-voted; an STB_LOCAL symbol is NEVER resolved
    // to another object's copy, so locals aren't a vote at all — they
    // are ground truth. Any disagreement among one node's locals means
    // the section was not placed as a single unit (an identity-model
    // violation), and the base build fails loud rather than recording
    // an address that resolves some references into the wrong bytes.
    struct Votes {
        /// (symbol name, back-computed section base) — names kept for
        /// the unanimity-violation diagnostic.
        local: Vec<(String, u64)>,
        other: Vec<u64>,
    }
    let mut votes: HashMap<u32, Votes> = HashMap::new();
    for (obj_idx, obj) in scan.objects.iter().enumerate() {
        for sym in &obj.symbols {
            let Some(sec_idx) = sym.defining_section else { continue };
            if sym.name.is_empty() { continue; }
            // TLS symbols' st_value in the final symtab is an offset
            // into the TLS template, NOT a virtual address — back-
            // computing `final − st_value` yields garbage (the map
            // oracle caught std's .tbss statics "recovered" at 0x20).
            // TLS sections get no table entry, so a positional
            // reference to one bails loudly instead of binding to a
            // nonsense address. (TLS-aware resolution is unsupported;
            // TPOFF-style relocs need TLS-segment arithmetic, not an
            // SHN_ABS anchor.)
            if obj.sections[sec_idx].sh_flags & u64::from(object::elf::SHF_TLS) != 0 {
                continue;
            }
            let Some(&nid) = node_of.get(&(obj_idx as u32, sec_idx as u32)) else { continue };
            let (key_tu, is_local) = match sym.bind {
                SymbolBind::Global | SymbolBind::Weak => (None, false),
                SymbolBind::Local => (Some(obj.tu_id), true),
            };
            let Some(Some(addr)) = final_addr.get(&(sym.name.clone(), key_tu)).copied() else {
                continue; // not in base symtab, or an ambiguous surrogate
            };
            let Some(base) = addr.checked_sub(sym.value) else { continue };
            let v = votes
                .entry(nid)
                .or_insert_with(|| Votes { local: Vec::new(), other: Vec::new() });
            if is_local {
                v.local.push((sym.name.clone(), base));
            } else {
                v.other.push(base);
            }
        }
    }

    // trans_hash → recovered base address. When several nodes share a
    // trans_hash at *different* addresses (content-identical sections base
    // did not fold — e.g. a tiny local helper duplicated across CGUs) we
    // keep one **representative** (the smallest, for determinism) and flag
    // the hash ambiguous. A named overlay reference to a multi-copy hash
    // resolves to base's exact copy by name when the name is unique
    // (genuinely distinct symbols that happen to be byte-identical);
    // same-name duplicates are interchangeable, so the representative is
    // sound. See `docs/14-identity-granularity.md`.
    let mut by_th: HashMap<[u8; 16], u64> = HashMap::new();
    let mut ambiguous: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    let mut node_addrs: HashMap<u32, u64> = HashMap::new();
    for (&nid, v) in &votes {
        // Aggregator nodes fold many contributor sections into one node;
        // a single "section base" is meaningless for them (and their
        // contributors' locals would trip the unanimity check below).
        // They resolve through bracket names via base_symtab (channel 3),
        // never positionally — keep them out of the table.
        if scan.graph.nodes[nid as usize].is_aggregator() {
            continue;
        }
        let base = if v.local.is_empty() {
            let Some(base) = majority(&v.other) else { continue };
            base
        } else {
            // Locals are ground truth and must agree exactly (see the
            // Votes doc above). Fail the BASE build on disagreement —
            // this is the self-check that turns an identity-model
            // violation into a build error instead of an overlay that
            // resolves references into the wrong bytes at runtime.
            let first = v.local[0].1;
            if v.local.iter().any(|&(_, b)| b != first) {
                let nm = &scan.graph.nodes[nid as usize];
                let mut evidence = String::new();
                for (name, b) in &v.local {
                    use std::fmt::Write;
                    let _ = write!(evidence, "\n    {name} → section base {b:#x}");
                }
                let where_ = nm
                    .segments
                    .first()
                    .map(|seg| {
                        let obj = &scan.objects[seg.object as usize];
                        format!(
                            "{} :: {}",
                            obj.tu_name,
                            obj.sections[seg.section as usize].name
                        )
                    })
                    .unwrap_or_else(|| "<no segments>".into());
                bail!(
                    "graft base self-check: STB_LOCAL symbols of one node disagree on \
                     its section base — the section was not placed as a unit, so \
                     positional resolution against it would be unsound.\n  node {nid} \
                     ({where_}):{evidence}"
                );
            }
            first
        };
        node_addrs.insert(nid, base);
        let th = scan.trans_hash[nid as usize];
        match by_th.entry(th) {
            Entry::Vacant(e) => {
                e.insert(base);
            }
            Entry::Occupied(mut e) => {
                if *e.get() != base {
                    ambiguous.insert(th);
                    if base < *e.get() {
                        e.insert(base); // keep the smallest as the representative
                    }
                }
            }
        }
    }

    let mut entries: Vec<SectionEntry> = by_th
        .into_iter()
        .map(|(trans_hash, address)| SectionEntry { trans_hash, address })
        .collect();
    entries.sort_by(|a, b| a.trans_hash.cmp(&b.trans_hash));
    let mut ambiguous: Vec<[u8; 16]> = ambiguous.into_iter().collect();
    ambiguous.sort();
    Ok((SectionTable { entries, ambiguous }, node_addrs))
}

/// Most frequent value (ties broken toward the smallest). `None` if empty.
fn majority(vals: &[u64]) -> Option<u64> {
    let mut counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for &v in vals {
        *counts.entry(v).or_insert(0) += 1;
    }
    let mut best: Option<(u64, usize)> = None;
    for (v, c) in counts {
        best = Some(match best {
            Some((bv, bc)) if bc > c || (bc == c && bv <= v) => (bv, bc),
            _ => (v, c),
        });
    }
    best.map(|(v, _)| v)
}

/// Same derivation as `elf::ParsedObject::tu_id` — blake3(file)[:8].
fn tu_id_from_file_name(name: &str) -> [u8; 8] {
    let digest = *blake3::hash(name.as_bytes()).as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn compute_base_abi(elf_bytes: &[u8]) -> [u8; 20] {
    // Prefer NT_GNU_BUILD_ID if present; otherwise fall back to
    // blake3(output ELF bytes) truncated to 20 bytes. Either is
    // sufficient for the "your overlay was built against a different
    // base" check M0.5 needs.
    if let Some(bid) = read_build_id(elf_bytes) {
        let mut out = [0u8; 20];
        let n = bid.len().min(20);
        out[..n].copy_from_slice(&bid[..n]);
        return out;
    }
    let digest = *blake3::hash(elf_bytes).as_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

fn read_build_id(elf_bytes: &[u8]) -> Option<Vec<u8>> {
    let elf = object::File::parse(elf_bytes).ok()?;
    elf.build_id().ok().flatten().map(|b| b.to_vec())
}

fn find_entry_symbol(elf_bytes: &[u8]) -> Option<String> {
    // `GRAFT_ENTRY_SYMBOL` overrides for debugging — moves the single
    // trampoline off `main` to a function the user controls, so they
    // can run code (printlns, memory probes) before the trampoline
    // fires and bisect crashes.
    if let Ok(s) = std::env::var("GRAFT_ENTRY_SYMBOL")
        && !s.is_empty()
    {
        return Some(s);
    }
    let _ = elf_bytes;
    Some("main".into())
}

fn toolchain_stamp() -> String {
    Command::new("rustc")
        .arg("-Vv")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.lines().find_map(|l| l.strip_prefix("commit-hash: ")).unwrap_or("?").to_string())
        .unwrap_or_else(|| "?".into())
}

/// Find `--flag value` or `--flag=value` in argv; return value if present.
pub(crate) fn extract_flag(argv: &[String], flag: &str) -> Option<String> {
    let prefix_eq = format!("{flag}=");
    let mut iter = argv.iter();
    while let Some(a) = iter.next() {
        if a == flag {
            return iter.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&prefix_eq) {
            return Some(v.to_string());
        }
    }
    None
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("graft-tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // Preserve executable bit from the original (rustc linked it
    // executable; std::fs::rename doesn't copy perms for newly-created
    // files).
    if let Ok(orig_meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = orig_meta.permissions().mode();
        let mut p = std::fs::metadata(&tmp)?.permissions();
        p.set_mode(mode);
        std::fs::set_permissions(&tmp, p)?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

