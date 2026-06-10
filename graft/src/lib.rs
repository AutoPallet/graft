//! graft — incremental compilation overlays for bare-metal Rust.
//!
//! This library surface mirrors the binary's entry points so integration
//! tests can drive work in-process. See `docs/06-graft-wrapper.md`.

pub mod arch;
pub mod archive;
pub mod argv;
pub mod base;
pub mod combine;
pub mod debug_dump;
pub mod elf;
pub mod elf_attach;
pub mod graph;
pub mod hash;
pub mod metadata;
pub mod overlay;
pub mod prune;
pub mod roots;
pub mod scan;
pub mod slack;
pub mod subcommands;
pub mod synthetic;
pub mod telemetry;

pub use metadata::{GRAFT_MAGIC, GraftManifest, SCHEMA_VERSION, SectionEntry, SectionTable};
