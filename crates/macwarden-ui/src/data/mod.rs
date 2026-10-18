//! The panel data layer: snapshot [`model`] types, the [`source`] trait, and
//! the deterministic [`demo`] source. The macOS-only live source lives in the
//! sibling `ui` module tree because it depends on `sysinfo`/`procmon`.

pub mod demo;
pub mod map;
pub mod model;
pub mod nettop;
pub mod openbinary;
pub mod prefs;
pub mod select;
pub mod source;
pub mod sweep;
pub mod trace_model;

#[cfg(unix)]
pub mod daemon;
#[cfg(unix)]
pub mod trace;
