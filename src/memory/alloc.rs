//! Memory allocation for hook structures.
//!
//! Allocates executable memory via `mmap` for hook trampolines and relocated
//! instruction buffers. Maintains a global registry of active hooks so that
//! multiple wrappers on the same function share a chain.

use crate::error::{HookError, HookResult};
use std::collections::HashMap;
use std::sync::Mutex;

/// Size of a single page for hook allocations (64 KiB is typical on aarch64).
const HOOK_PAGE_SIZE: usize = 0x10000; // 64 KiB

/// Wrapper around `*mut u8` that implements `Send` + `Sync`.
///
/// # Safety
///
/// The pointers stored here are allocated via `mmap` and are only accessed
/// under the mutex lock within this module.
#[derive(Clone, Copy)]
struct HookPtr(*mut u8);

unsafe impl Send for HookPtr {}
unsafe impl Sync for HookPtr {}

/// Global hook registry: maps origin addresses to allocated hook memory.
static HOOK_REGISTRY: std::sync::LazyLock<Mutex<HashMap<usize, HookPtr>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Allocate executable memory suitable for storing hook structures and
/// relocated instruction sequences.
///
/// Returns a pointer to the allocated memory (page-aligned, RWX).
pub fn hook_mem_alloc(size: usize) -> HookResult<*mut u8> {
    let alloc_size = crate::utils::align_ceil(size as u64, HOOK_PAGE_SIZE as u64) as usize;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(HookError::NoMem);
    }

    Ok(ptr as *mut u8)
}

/// Free hook memory allocated by `hook_mem_alloc`.
pub fn hook_mem_free(ptr: *mut u8, size: usize) {
    let alloc_size = crate::utils::align_ceil(size as u64, HOOK_PAGE_SIZE as u64) as usize;
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, alloc_size);
    }
}

/// Register a hook by its origin address. Returns an error if a hook
/// already exists at this address.
pub fn hook_mem_register(origin_addr: usize, ptr: *mut u8) -> HookResult<()> {
    let mut reg = HOOK_REGISTRY.lock().unwrap();
    if reg.contains_key(&origin_addr) {
        return Err(HookError::Duplicated);
    }
    reg.insert(origin_addr, HookPtr(ptr));
    Ok(())
}

/// Look up a previously registered hook by its origin address.
pub fn hook_mem_lookup(origin_addr: usize) -> Option<*mut u8> {
    let reg = HOOK_REGISTRY.lock().unwrap();
    reg.get(&origin_addr).map(|h| h.0)
}

/// Remove a hook from the registry.
pub fn hook_mem_unregister(origin_addr: usize) {
    let mut reg = HOOK_REGISTRY.lock().unwrap();
    reg.remove(&origin_addr);
}
