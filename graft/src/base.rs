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
use object::Object;

use crate::argv;
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

    // The linker map is base's address-recovery source (see `mapcheck`):
    // it states every input section's placed address, size, and — on
    // relaxing targets — the pre-relaxation size, none of which can be
    // recovered from symbols once ld rewrites section interiors. Always
    // requested; kept next to the output for debugging.
    let map_path = output.with_extension("graft-map");
    argv.push(format!("-Wl,-Map={}", map_path.display()));
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
    check_slack_scooped(&elf_bytes)?;
    if let Ok(p) = std::env::var("GRAFT_DEBUG_DUMP_GRAPH")
        && !p.is_empty()
    {
        if let Err(e) = crate::debug_dump::dump_graph(std::path::Path::new(&p), &scan_result) {
            eprintln!("graft base: GRAFT_DEBUG_DUMP_GRAPH write {p} failed: {e}");
        }
    }
    let map_text = std::fs::read_to_string(&map_path)
        .with_context(|| format!("read linker map {}", map_path.display()))?;
    let map = crate::mapcheck::parse_map(&map_text);
    let (table, stats, dups) = build_section_table(&scan_result, &elf_bytes, &map, arch)?;
    print_dup_summary(&dups);
    eprintln!(
        "graft base map-recovery: {} attributed ({} byte-identical · {} reconciled \
         through relaxation · {} no-bytes) · {} dropped unreconciled · \
         {} ambiguous-key skipped · {} size-mismatch skipped",
        stats.attributed,
        stats.verified,
        stats.verified_relaxed,
        stats.unverifiable,
        stats.dropped,
        stats.skipped_ambiguous,
        stats.skipped_size_mismatch,
    );

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

/// One-line dedup-miss summary, printed on every base link. The full
/// per-group listing lives behind `graft dup-stats` (subcommands.rs).
fn print_dup_summary(dups: &[DupGroup]) {
    if dups.is_empty() {
        return;
    }
    let (mut exec_waste, mut ro_waste, mut copies) = (0u64, 0u64, 0usize);
    for d in dups {
        copies += d.placements.len() - 1;
        if d.exec {
            exec_waste += d.wasted_bytes();
        } else {
            ro_waste += d.wasted_bytes();
        }
    }
    eprintln!(
        "graft base dedup-miss: {} content-identical groups · {} redundant copies · \
         {} bytes exec + {} bytes non-exec unfolded (ld has no ICF)",
        dups.len(),
        copies,
        exec_waste,
        ro_waste,
    );
}

/// Replay scan + map-recovery against an existing base link (no
/// relink) and print the full duplicate-placement report. Driven by
/// `graft dup-stats` — see subcommands.rs for the CLI.
pub(crate) fn dup_stats(
    argv_file: &std::path::Path,
    elf_path: &std::path::Path,
    map_path: &std::path::Path,
) -> Result<()> {
    let text = std::fs::read_to_string(argv_file)
        .with_context(|| format!("read argv file {}", argv_file.display()))?;
    let mut argv: Vec<String> = vec!["graft".into()];
    argv.extend(text.lines().filter(|l| !l.is_empty()).map(str::to_string));
    if let Some(cwd) = extract_flag(&argv, "--ldproxy-cwd") {
        std::env::set_current_dir(&cwd)
            .with_context(|| format!("chdir to --ldproxy-cwd {cwd}"))?;
    }
    let link_args = argv::parse(&argv);
    let driver = crate::argv::driver_path(&argv);
    let (eager, deferred) = crate::overlay::resolve_scan_inputs(&link_args, &driver);
    let entry = find_entry_symbol(&[]);
    let scan_result = scan::run(
        &eager,
        &deferred,
        &link_args.undefined,
        &link_args.wrapped,
        entry.as_deref(),
    )
    .context("scan")?;
    let elf_bytes =
        std::fs::read(elf_path).with_context(|| format!("read {}", elf_path.display()))?;
    let map_text =
        std::fs::read_to_string(map_path).with_context(|| format!("read {}", map_path.display()))?;
    let map = crate::mapcheck::parse_map(&map_text);
    let arch = crate::slack::detect_architecture(&link_args.inputs)
        .context("detect target architecture from input objects")?;
    let (_table, stats, dups) = build_section_table(&scan_result, &elf_bytes, &map, arch)?;

    println!(
        "dup-stats: {} nodes attributed · {} groups placed at >1 address",
        stats.attributed,
        dups.len(),
    );
    let (mut exec_waste, mut ro_waste) = (0u64, 0u64);
    for d in &dups {
        if d.exec {
            exec_waste += d.wasted_bytes();
        } else {
            ro_waste += d.wasted_bytes();
        }
    }
    println!("redundant bytes: {exec_waste} exec · {ro_waste} non-exec");
    println!();
    for d in &dups {
        let h: String = d.trans_hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
        println!(
            "x{:<3} waste {:>8}  {}  th={h}  {}  [{}]",
            d.placements.len(),
            d.wasted_bytes(),
            if d.exec { "exec" } else { "data" },
            d.section,
            d.placements
                .iter()
                .map(|&(a, s)| format!("{a:#x}+{s:#x}"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
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
    argv.push(format!("-Wl,--undefined={}", crate::slack::TLS_SYMBOL));
    Ok(argv)
}

/// The slack sections only work if the target's linker script scoops
/// them into base's normal output sections via wildcards (`*(.text.*)`
/// etc. — see `slack.rs` module docs). A script with no matching rule
/// makes ld *orphan-place* the input section: it survives under its own
/// name, lands wherever ld guesses, and can silently change segment
/// layout (on esp32s3, an orphaned `.tdata.graft_slack` joined the IROM
/// LOAD, flipped it writable, and the ROM bootloader rejected the image
/// — a boot crash-loop with no link-time symptom). An output section
/// still carrying a `.graft_slack` input name is exactly that signature;
/// fail the base build instead of shipping the image.
fn check_slack_scooped(elf_bytes: &[u8]) -> Result<()> {
    use object::{Object, ObjectSection};
    let elf = object::File::parse(elf_bytes).context("parse output ELF")?;
    for sec in elf.sections() {
        let name = sec.name().unwrap_or("");
        if name.ends_with(".graft_slack") {
            let hint = if name.starts_with(".tdata") {
                "If this target has no TLS runtime, set GRAFT_TLS_SLACK_LEN=0; \
                 otherwise add a `*(.tdata .tdata.*)` rule to the script."
            } else {
                "Splice mode needs this region — add the matching wildcard \
                 rule to the linker script."
            };
            bail!(
                "graft base self-check: the linker script did not scoop `{name}` — \
                 ld orphan-placed it, which silently changes segment layout. {hint}"
            );
        }
    }
    Ok(())
}

fn exec_real_linker(argv: &[String]) -> Result<std::process::ExitStatus> {
    let real = std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&real)
        .args(&argv[1..])
        .status()
        .with_context(|| format!("exec {real}"))?;
    Ok(status)
}

/// Build the `.graft.sections` table: where did base place each input
/// section, keyed by the section's `trans_hash`.
///
/// Addresses and placed sizes come from the **linker map** — ld's own
/// record, and the only source that survives relaxation (back-computing
/// from symbols drifts the moment ld deletes bytes inside a section).
/// Attribution is by exact key (object basename, archive member,
/// section name) plus input size; anything ambiguous is skipped, not
/// guessed (the node just isn't in the table, and an overlay reference
/// to it re-emits — always safe).
///
/// Every attributed claim is then **byte-verified** against the linked
/// image before it's recorded: masked compare, with the relaxation
/// walk as the slow path on xtensa (`relax::verify`). A claim the
/// bytes can't support is dropped with a count. This is the entire
/// integrity story — no symbol votes, no map-symbol cross-checks —
/// and it's strictly stronger wherever bytes exist: it verifies the
/// actual placement against ld's output. Sections with no bytes
/// anywhere (.bss) ride on the exact-key attribution alone; a key
/// collision there is refused as ambiguous rather than resolved.
///
/// Content-identical sections base placed at distinct addresses
/// (un-folded identical monomorphizations) collide on `trans_hash`; we
/// keep one representative address and flag the hash `ambiguous` so a
/// named reference can be disambiguated by name when the name is
/// unique. Aggregator brackets (`__init_array_start` etc.) and
/// SHF_MERGE / string-pool per-entry nodes are intentionally NOT in
/// this table — they resolve through other channels (symtab snapshot /
/// re-emission). See `docs/14-identity-granularity.md`, docs/16 §8.
fn build_section_table(
    scan: &ScanResult,
    elf_bytes: &[u8],
    map: &[crate::mapcheck::MapSection],
    arch: object::Architecture,
) -> Result<(SectionTable, RecoveryStats, Vec<DupGroup>)> {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;

    use crate::relax::verify::{self, LinkedImage, SectionCheck};

    if map.is_empty() {
        bail!(
            "graft base map-recovery: parsed zero input-section records — \
             wrong linker map format (is the real linker GNU ld?)"
        );
    }

    // (object basename, member, section name) → map records.
    let mut index: HashMap<(&str, Option<&str>, &str), Vec<&crate::mapcheck::MapSection>> =
        HashMap::new();
    for m in map {
        index
            .entry((m.object.as_str(), m.member.as_deref(), m.section.as_str()))
            .or_default()
            .push(m);
    }

    let mut stats = RecoveryStats::default();
    // Attributed placement claims: (node, object, section, record).
    let mut attributed: Vec<(u32, u32, u32, &crate::mapcheck::MapSection)> = Vec::new();
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        if nm.is_aggregator() {
            continue; // many contributors, no single base address
        }
        let [seg] = nm.segments.as_slice() else { continue };
        if seg.range.is_some() {
            continue; // per-string / per-merge-entry nodes re-emit, never positional
        }
        let obj = &scan.objects[seg.object as usize];
        let sec = &obj.sections[seg.section as usize];
        if sec.sh_flags & u64::from(object::elf::SHF_ALLOC) == 0 {
            continue; // never placed; map "addresses" would be vma-0 offsets
        }
        if sec.sh_flags & u64::from(object::elf::SHF_MERGE) != 0 {
            continue; // ld shuffles entries; the section address says nothing
        }
        let input = &scan.inputs[seg.object as usize];
        let obj_name = input
            .source_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let key = (obj_name, input.member_name.as_deref(), sec.name.as_str());
        let Some(records) = index.get(&key) else {
            continue; // gc'd by ld, or the member wasn't loaded
        };
        // ld's input size must equal ours. A mismatch means the record
        // isn't this section — or ld structurally edited it (.eh_frame
        // CIE dedup), in which case positional anchoring is wrong anyway.
        let matching: Vec<&&crate::mapcheck::MapSection> =
            records.iter().filter(|r| r.in_size == sec.sh_size).collect();
        match matching.len() {
            1 => attributed.push((nid as u32, seg.object, seg.section, matching[0])),
            0 => stats.skipped_size_mismatch += 1,
            // Same name AND same size twice in one object (the .rwtext
            // twins): indistinguishable — refuse rather than guess.
            _ => stats.skipped_ambiguous += 1,
        }
    }
    stats.attributed = attributed.len();
    if attributed.is_empty() {
        bail!(
            "graft base map-recovery: zero nodes attributed to map records — \
             object/section key derivation is broken"
        );
    }

    // Byte-verify every claim against the linked image (docs/16 §8):
    // masked compare, then (xtensa) the transform walk. One object
    // parse per object, fanned out across cores.
    let image = LinkedImage::new(elf_bytes).map_err(|e| anyhow!("parse linked image: {e}"))?;
    let lit_syms = if matches!(arch, object::Architecture::Xtensa) {
        let elf = object::File::parse(elf_bytes).context("parse output ELF")?;
        verify::unique_symbol_addrs(&elf)
    } else {
        HashMap::new()
    };
    let mut by_obj: HashMap<u32, Vec<(u32, u32, &crate::mapcheck::MapSection)>> = HashMap::new();
    for &(nid, obj, sec, rec) in &attributed {
        by_obj.entry(obj).or_default().push((nid, sec, rec));
    }
    enum Checked {
        NoBytes,
        Identical,
        Reconciled,
        Drop(String),
    }
    use rayon::prelude::*;
    let by_obj: Vec<_> = by_obj.into_iter().collect();
    let outcomes: Vec<(u32, &crate::mapcheck::MapSection, Checked)> = by_obj
        .par_iter()
        .flat_map(|(obj, entries)| {
            let file = object::File::parse(&*scan.inputs[*obj as usize].bytes);
            entries
                .iter()
                .map(|&(nid, sec_idx, rec)| {
                    let sinfo = &scan.objects[*obj as usize].sections[sec_idx as usize];
                    if sinfo.bytes.is_empty() {
                        // NOBITS / zero-size: nothing to match anywhere.
                        // The claim rides on the exact key + size alone.
                        return (nid, rec, Checked::NoBytes);
                    }
                    let checked = (|| {
                        let file = match &file {
                            Ok(f) => f,
                            Err(e) => return Checked::Drop(format!("reparse object: {e}")),
                        };
                        let Some(out) = image.slice(rec.address, rec.out_size) else {
                            return Checked::Drop(format!(
                                "no linked bytes at {:#x}+{:#x}",
                                rec.address, rec.out_size
                            ));
                        };
                        let osec = match file
                            .section_by_index(object::SectionIndex(sec_idx as usize + 1))
                        {
                            Ok(s) => s,
                            Err(e) => return Checked::Drop(format!("section by index: {e}")),
                        };
                        let input = match verify::input_view(arch, file, &osec, &lit_syms) {
                            Ok(i) => i,
                            Err(e) => return Checked::Drop(format!("extract input: {e}")),
                        };
                        match verify::check_section(arch, &input, out) {
                            SectionCheck::Identical => Checked::Identical,
                            SectionCheck::Reconciled => Checked::Reconciled,
                            SectionCheck::Dirty(why) => Checked::Drop(why),
                        }
                    })();
                    (nid, rec, checked)
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // trans_hash → placed (address, out_size). When several nodes share
    // a trans_hash at *different* addresses (content-identical sections
    // base did not fold) we keep one representative (the smallest, for
    // determinism) and flag the hash ambiguous.
    let mut by_th: HashMap<[u8; 16], (u64, u64)> = HashMap::new();
    let mut ambiguous: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    let mut dropped_examples: Vec<String> = Vec::new();
    // Every placement per hash, for the dedup-miss report (ld has no
    // ICF; content-identical copies it kept are pure image waste).
    let mut placements: HashMap<[u8; 16], Vec<(u64, u64)>> = HashMap::new();
    let mut dup_meta: HashMap<[u8; 16], (String, String, bool)> = HashMap::new();
    for (nid, rec, checked) in outcomes {
        match checked {
            Checked::NoBytes => stats.unverifiable += 1,
            Checked::Identical => stats.verified += 1,
            Checked::Reconciled => stats.verified_relaxed += 1,
            Checked::Drop(why) => {
                stats.dropped += 1;
                if dropped_examples.len() < 20 {
                    dropped_examples
                        .push(format!("  {} {} @{:#x}: {why}", rec.section, rec.path, rec.address));
                }
                continue;
            }
        }
        let th = scan.trans_hash[nid as usize];
        placements.entry(th).or_default().push((rec.address, rec.out_size));
        dup_meta.entry(th).or_insert_with(|| {
            let seg = &scan.graph.nodes[nid as usize].segments[0];
            let sh_flags =
                scan.objects[seg.object as usize].sections[seg.section as usize].sh_flags;
            let exec = sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0;
            (rec.section.clone(), rec.path.clone(), exec)
        });
        match by_th.entry(th) {
            Entry::Vacant(e) => {
                e.insert((rec.address, rec.out_size));
            }
            Entry::Occupied(mut e) => {
                if e.get().0 != rec.address {
                    ambiguous.insert(th);
                    if rec.address < e.get().0 {
                        e.insert((rec.address, rec.out_size));
                    }
                }
            }
        }
    }
    let mut dups: Vec<DupGroup> = Vec::new();
    for (th, mut addrs) in placements {
        addrs.sort();
        addrs.dedup();
        if addrs.len() < 2 {
            continue;
        }
        let (section, path, exec) = dup_meta.remove(&th).unwrap_or_default();
        dups.push(DupGroup { trans_hash: th, section, path, exec, placements: addrs });
    }
    dups.sort_by_key(|d| std::cmp::Reverse(d.wasted_bytes()));
    if stats.dropped > 0 {
        eprintln!(
            "graft base map-recovery: {} placement claim(s) failed byte \
             verification and were dropped (references re-emit):\n{}",
            stats.dropped,
            dropped_examples.join("\n"),
        );
    }

    let mut entries: Vec<SectionEntry> = by_th
        .into_iter()
        .map(|(trans_hash, (address, out_size))| SectionEntry { trans_hash, address, out_size })
        .collect();
    entries.sort_by(|a, b| a.trans_hash.cmp(&b.trans_hash));
    let mut ambiguous: Vec<[u8; 16]> = ambiguous.into_iter().collect();
    ambiguous.sort();
    Ok((SectionTable { entries, ambiguous }, stats, dups))
}

/// One `trans_hash` that base placed at more than one address:
/// content-identical, reloc-identical (transitively) sections ld kept
/// as separate copies because it has no ICF. Every copy past the first
/// is redundant image bytes.
pub(crate) struct DupGroup {
    pub trans_hash: [u8; 16],
    /// Representative input section name (diagnostic).
    pub section: String,
    /// Representative input path (diagnostic).
    pub path: String,
    pub exec: bool,
    /// (address, out_size) per distinct placement, address-sorted.
    pub placements: Vec<(u64, u64)>,
}

impl DupGroup {
    /// Bytes the image would shed if all copies folded to one: total
    /// placed size minus the largest copy (copies can relax to
    /// different sizes at different addresses).
    pub(crate) fn wasted_bytes(&self) -> u64 {
        let total: u64 = self.placements.iter().map(|&(_, s)| s).sum();
        total - self.placements.iter().map(|&(_, s)| s).max().unwrap_or(0)
    }
}

#[derive(Default)]
struct RecoveryStats {
    /// Nodes attributed to exactly one map record (key + size).
    attributed: usize,
    /// Key collisions the size filter couldn't split.
    skipped_ambiguous: usize,
    /// Keyed records whose input size didn't match ours (.eh_frame &c).
    skipped_size_mismatch: usize,
    /// Byte-identical at the claimed address (modulo reloc fields).
    verified: usize,
    /// xtensa: explained by the relaxation walk.
    verified_relaxed: usize,
    /// No bytes to check (.bss / zero-size) — kept on attribution alone.
    unverifiable: usize,
    /// Claims the bytes refused — NOT recorded in the table.
    dropped: usize,
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

