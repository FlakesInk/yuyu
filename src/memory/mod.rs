//! Memory management and code-patching utilities.
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`alloc`] | `mmap`-based executable memory allocation + global hook registry |
//! | [`cache`] | Instruction / data cache maintenance (`flush_icache`) |
//! | [`protect`] | `mprotect` wrappers and `hotpatch` for safe code overwriting |

pub mod alloc;
pub mod cache;
pub mod protect;
