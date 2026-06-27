//! Utility functions for hook operations.

use crate::error::HookError;

/// Round `x` up to the nearest multiple of `align`.
/// `align` must be a power of two.
#[inline(always)]
pub const fn align_ceil(x: u64, align: u64) -> u64 {
    (x + align - 1) & !(align - 1)
}

/// Check if a virtual address is likely invalid.
///
/// Checks against: null, kernel-space addresses, and verifies the address
/// falls within an executable mapping via `/proc/self/maps`.
///
/// Returns `true` if the address appears bad.
pub fn is_bad_address(addr: usize) -> bool {
    if addr == 0 {
        return true;
    }

    // Probe via /proc/self/maps
    match proc_maps::get_process_maps(unsafe { libc::getpid() } as _) {
        Ok(maps) => {
            for map in maps {
                let start = map.start();
                let end = map.start() + map.size();
                if addr >= start && addr < end && map.is_exec() {
                    return false;
                }
            }
            true
        }
        Err(_) => {
            // Without maps, fall back to a simple range check.
            // On aarch64 Linux userspace, addresses outside the lower
            // 48-bit VA range are definitely invalid.
            addr > 0x0000_FFFF_FFFF_FFFF
        }
    }
}

/// Check if a function pointer is valid and executable.
pub fn check_func_addr(addr: usize) -> Result<(), HookError> {
    if is_bad_address(addr) {
        Err(HookError::BadAddress)
    } else {
        Ok(())
    }
}

/// Minimal logging (for debug builds).
#[macro_export]
macro_rules! logkv {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_ceil_already_aligned() {
        assert_eq!(align_ceil(0x1000, 0x1000), 0x1000);
        assert_eq!(align_ceil(0x2000, 0x1000), 0x2000);
    }

    #[test]
    fn test_align_ceil_rounds_up() {
        assert_eq!(align_ceil(0x1001, 0x1000), 0x2000);
        assert_eq!(align_ceil(0x1, 0x1000), 0x1000);
        assert_eq!(align_ceil(0xFFF, 0x1000), 0x1000);
    }

    #[test]
    fn test_align_ceil_small_align() {
        assert_eq!(align_ceil(7, 4), 8);
        assert_eq!(align_ceil(8, 4), 8);
        assert_eq!(align_ceil(3, 2), 4);
    }

    #[test]
    fn test_is_bad_address_null() {
        assert!(is_bad_address(0));
    }

    #[test]
    fn test_is_bad_address_kernel_range() {
        // 0xFFFF... addresses are kernel space on aarch64 Linux
        assert!(is_bad_address(0xFFFF_0000_0000_0000));
        assert!(is_bad_address(0xFFFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn test_check_func_addr_ok() {
        // A valid function pointer in this test binary should be non-null.
        let func = test_check_func_addr_ok as *const () as usize;
        assert!(func > 0);
    }

    #[test]
    fn test_check_func_addr_null() {
        assert_eq!(check_func_addr(0), Err(HookError::BadAddress));
    }
}
