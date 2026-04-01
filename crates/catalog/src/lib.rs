//! `catalog` — service annotation database, plist parsing, and
//! service discovery.
//!
//! This crate is responsible for:
//! - Parsing macOS launchd plist files (binary and XML)
//! - Maintaining an annotation database that maps service labels to categories,
//!   safety levels, and human-readable descriptions
//! - Discovering services by enumerating plist directories
//! - Combining plist data with annotations to produce full [`ServiceInfo`] records
//!
//! # Modules
//!
//! - [`annotation`] — `ServiceAnnotation`, `AnnotationDb` with exact + glob lookup
//! - [`builtin`] — Embedded TOML with ~50 common macOS service annotations
//! - [`plist_parser`] — `PlistInfo` and `parse_plist()` for XML/binary plists
//! - [`discovery`] — `discover_plists()`, `annotate_services()`, `DEFAULT_PLIST_DIRS`
//! - [`error`] — `CatalogError` variants

pub mod annotation;
pub mod discovery;
pub mod error;
pub mod loader;
pub mod plist_parser;

// Re-export key items at crate root for convenience.
pub use annotation::{AnnotationDb, ServiceAnnotation};
pub use discovery::{DEFAULT_PLIST_DIRS, annotate_services, discover_plists};
pub use error::CatalogError;
pub use loader::{load_builtin_annotations, load_builtin_groups, load_builtin_profiles};
pub use plist_parser::{PlistInfo, parse_plist};
