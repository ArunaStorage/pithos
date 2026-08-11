//! Private current-format byte grammar.
//!
//! This module deliberately contains no archive policy, filesystem, adapter, or
//! transport concerns.

pub(crate) mod codec;
pub(crate) mod directory;
pub(crate) mod entries;
pub(crate) mod error;
pub(crate) mod limits;
pub(crate) mod wire;
