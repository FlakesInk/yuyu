//! Memory protection utilities for making code pages writable/executable.
//!
//! Provides safe wrappers around `mprotect` for applying code patches
//! (trampolines, relocated instructions) at runtime.

use crate::error::{HookError, HookResult};

/// Memory protection flags (matching libc constants).
const PROT_READ: libc::c_int = 1;
const PROT_WRITE: libc::c_int = 2;
const PROT_EXEC: libc::c_int = 4;

/// Align address down to page boundary.
#[inline]
fn page_align_down(addr: usize) -> usize {
    addr & !(page_size() - 1)
}

/// Get the system page size (cached after first call).
fn page_size() -> usize {
    use std::sync::OnceLock;
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize })
}

/// Make a memory region writable.
///
/// # Safety
///
/// The caller must ensure `addr` points to valid mapped memory and `len` is within bounds.
pub unsafe fn make_writable(addr: *const u8, len: usize) -> HookResult<()> {
    let page_addr = page_align_down(addr as usize);
    let ret = unsafe {
        libc::mprotect(
            page_addr as *mut libc::c_void,
            len + (addr as usize - page_addr),
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
    };
    if ret != 0 {
        Err(HookError::MemoryProtection)
    } else {
        Ok(())
    }
}

/// Make a memory region read+exec only (restore after patching).
///
/// # Safety
///
/// The caller must ensure `addr` points to valid mapped memory and `len` is within bounds.
pub unsafe fn make_executable(addr: *const u8, len: usize) -> HookResult<()> {
    let page_addr = page_align_down(addr as usize);
    let ret = unsafe {
        libc::mprotect(
            page_addr as *mut libc::c_void,
            len + (addr as usize - page_addr),
            PROT_READ | PROT_EXEC,
        )
    };
    if ret != 0 {
        Err(HookError::MemoryProtection)
    } else {
        Ok(())
    }
}

/// Apply a code patch: write `new_insts` (u32 words) to `dst` with proper
/// memory protection and instruction cache maintenance.
///
/// # Safety
///
/// `dst` must point to valid executable memory with at least `count * 4` bytes.
/// `new_insts` must contain at least `count` valid instruction words.
#[inline(never)]
pub unsafe fn hotpatch(dst: *mut u32, new_insts: &[u32], count: usize) -> HookResult<()> {
    if count == 0 {
        return Ok(());
    }

    let addr = dst as *const u8;
    let len = count * 4;

    // Make writable
    unsafe { make_writable(addr, len)? };

    // Write instructions
    for (i, &inst) in new_insts.iter().enumerate().take(count) {
        unsafe {
            *dst.add(i) = inst;
        }
    }

    // Flush data cache and invalidate instruction cache
    unsafe {
        super::cache::flush_icache(addr as *mut u8, len);
    }

    // Restore read+exec
    unsafe { make_executable(addr, len)? };

    Ok(())
}
