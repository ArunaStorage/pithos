//! Presentation adapters for external archive formats.
//!
//! Adapters own presentation-specific parsing, retained-source handling, and error
//! context. Core archive, format, block, and crypto code do not own RO-Crate, ZIP,
//! Crypt4GH, or host filesystem error types.

pub mod crypt4gh;
pub mod ro_crate;
