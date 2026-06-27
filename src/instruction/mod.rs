//! ARM64 instruction encoding / decoding tools.
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`bit`] | Bit-manipulation primitives (`bits32`, `sign_extend`) |
//! | [`decoder`] | Instruction classification and field extraction |
//! | [`writer`] | Machine-code generation (branches, relocation sequences) |
//! | [`reloc`] | High-level instruction relocation for hooks |

pub mod bit;
pub mod decoder;
pub mod reloc;
pub mod writer;
