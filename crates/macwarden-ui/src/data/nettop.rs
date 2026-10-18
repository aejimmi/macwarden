//! Re-export of the shared `nettop` parser.
//!
//! The parser and the macOS subprocess sampler now live in the `netsample`
//! workspace crate so the daemon and the panel share one implementation. This
//! module keeps the `crate::data::nettop::{parse, ProcNet, Conn}` paths stable
//! for the live source. The moved parser tests live alongside it in `netsample`.

pub use netsample::{Conn, ProcNet, parse};
