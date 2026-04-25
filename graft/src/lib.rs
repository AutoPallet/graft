//! graft — incremental compilation for bare-metal Rust.
//!
//! Single-ELF model: graft acts as the linker (driven via `-C linker=`),
//! produces a normal ELF on every build. On a clean build (`GRAFT=base`)
//! it captures per-section layout. On subsequent builds (`GRAFT=
//! incremental`) it pins unchanged sections to base addresses so the
//! resulting `.img` differs from base's `.img` only where source
//! actually changed — `scripts/pageflash.py` then range-writes only
//! those pages.

pub mod archive;
pub mod argv;
pub mod base;
pub mod elf;
pub mod graph;
pub mod hash;
pub mod incremental;
pub mod metadata;
pub mod scan;
pub mod subcommands;
pub mod telemetry;

pub use metadata::{BaseLayout, GRAFT_MAGIC, SCHEMA_VERSION, SectionLayout};
