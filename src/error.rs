//! Error types for the hook library.

use std::fmt;

/// Errors that can occur during hook operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookError {
    /// No memory available for hook allocation.
    NoMem,
    /// The target address is invalid or inaccessible.
    BadAddress,
    /// Instruction relocation failed (unsupported instruction or out of range).
    BadRelo,
    /// A hook chain callback with the same function pointer already exists.
    Duplicated,
    /// The hook chain is full (max number of callbacks reached).
    ChainFull,
    /// Insufficient space in the transit buffer.
    TransitNoMem,
    /// Failed to modify memory protection.
    MemoryProtection,
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookError::NoMem => write!(f, "no memory available for hook"),
            HookError::BadAddress => write!(f, "invalid or inaccessible address"),
            HookError::BadRelo => write!(f, "instruction relocation failed"),
            HookError::Duplicated => write!(f, "callback already exists in chain"),
            HookError::ChainFull => write!(f, "hook chain is full"),
            HookError::TransitNoMem => write!(f, "insufficient transit buffer space"),
            HookError::MemoryProtection => write!(f, "failed to modify memory protection"),
        }
    }
}

impl std::error::Error for HookError {}

/// Result type alias for hook operations.
pub type HookResult<T> = Result<T, HookError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        assert_eq!(HookError::NoMem.to_string(), "no memory available for hook");
        assert_eq!(
            HookError::BadAddress.to_string(),
            "invalid or inaccessible address"
        );
        assert_eq!(
            HookError::BadRelo.to_string(),
            "instruction relocation failed"
        );
        assert_eq!(
            HookError::Duplicated.to_string(),
            "callback already exists in chain"
        );
        assert_eq!(HookError::ChainFull.to_string(), "hook chain is full");
        assert_eq!(
            HookError::TransitNoMem.to_string(),
            "insufficient transit buffer space"
        );
        assert_eq!(
            HookError::MemoryProtection.to_string(),
            "failed to modify memory protection"
        );
    }

    #[test]
    fn error_debug_clone() {
        let e = HookError::NoMem;
        let cloned = e;
        assert_eq!(e, cloned);
        assert_eq!(format!("{:?}", e), "NoMem");
    }
}
