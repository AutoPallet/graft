//! graft — incremental compilation overlays for bare-metal Rust.
//!
//! This library surface mirrors the binary's entry points so integration
//! tests can drive work in-process. See `docs/worklogs/06-graft-wrapper.md`.

pub mod anchor_verify;
pub mod arch;
pub mod archive;
pub mod argv;
pub mod auto;
pub mod base;
pub mod basemap;
pub mod combine;
pub mod debug_dump;
pub mod debug_flags;
pub mod elf;
pub mod elf_attach;
pub mod graph;
pub mod hash;
pub mod icf;
pub mod mapcheck;
pub mod metadata;
pub mod overlay;
pub mod prune;
pub mod relax;
pub mod resolve;
pub mod roots;
pub mod scan;
pub mod slack;
pub mod subcommands;
pub mod synthetic;
pub mod telemetry;

pub use metadata::{GRAFT_MAGIC, GraftManifest, SCHEMA_VERSION, SectionEntry, SectionTable};
