//! Low-level inline hook implementation.
//!
//! Provides `hook_prepare`, `hook_install`, `hook_uninstall`, and the
//! public `hook` / `unhook` API. Handles instruction backup, trampoline
//! generation, instruction relocation, and code patching.

use crate::error::{HookError, HookResult};
use crate::hook::context::*;
use crate::hook::patch::resolve_branch;
use crate::instruction::decoder::{ARM64_BTI_JC, ARM64_NOP, ARM64_PACIASP, ARM64_PACIBSP};
use crate::instruction::reloc::relocate_inst;
use crate::instruction::writer;
use crate::memory::{alloc, protect};
use crate::utils;

// ---------------------------------------------------------------------------
// Core hook operations
// ---------------------------------------------------------------------------

/// Prepare a hook for installation.
#[inline(never)]
pub fn hook_prepare(hook: &mut Hook) -> HookResult<()> {
    // Validate all addresses
    utils::check_func_addr(hook.func_addr as usize)?;
    utils::check_func_addr(hook.origin_addr as usize)?;
    utils::check_func_addr(hook.replace_addr as usize)?;
    utils::check_func_addr(hook.relo_addr as usize)?;

    // Backup original instructions
    for i in 0..TRAMPOLINE_MAX_NUM {
        hook.origin_insts[i] = unsafe { *((hook.origin_addr as *const u32).add(i)) };
    }

    // Build trampoline to replace_addr
    if hook.origin_insts[0] == ARM64_PACIASP || hook.origin_insts[0] == ARM64_PACIBSP {
        hook.tramp_insts_num = writer::branch_from_to(
            &mut hook.tramp_insts[1..],
            hook.origin_addr,
            hook.replace_addr,
        ) as i32;
        hook.tramp_insts[0] = ARM64_BTI_JC;
        hook.tramp_insts_num += 1;
    } else {
        hook.tramp_insts_num =
            writer::branch_from_to(&mut hook.tramp_insts, hook.origin_addr, hook.replace_addr)
                as i32;
    }

    // Clear relocated instruction buffer
    for inst in hook.relo_insts.iter_mut() {
        *inst = ARM64_NOP;
    }

    // Relocate each overwritten instruction
    for i in 0..hook.tramp_insts_num as usize {
        let inst_addr = hook.origin_addr + i as u64 * 4;
        let inst = hook.origin_insts[i];
        relocate_inst(hook, inst_addr, inst)?;
    }

    // Add jump-back from relocated code to after the trampoline
    let back_src = hook.relo_addr + hook.relo_insts_num as u64 * 4;
    let back_dst = hook.origin_addr + hook.tramp_insts_num as u64 * 4;
    let buf_start = hook.relo_insts_num as usize;
    let written = writer::branch_from_to(&mut hook.relo_insts[buf_start..], back_src, back_dst);
    hook.relo_insts_num += written as i32;

    Ok(())
}

/// Install a prepared hook by patching the original code.
#[inline(never)]
pub fn hook_install(hook: &Hook) -> HookResult<()> {
    let dst = hook.origin_addr as *mut u32;
    let count = hook.tramp_insts_num as usize;
    unsafe { protect::hotpatch(dst, &hook.tramp_insts, count) }
}

/// Uninstall a hook by restoring the original instructions.
#[inline(never)]
pub fn hook_uninstall(hook: &Hook) -> HookResult<()> {
    let dst = hook.origin_addr as *mut u32;
    let count = hook.tramp_insts_num as usize;
    unsafe { protect::hotpatch(dst, &hook.origin_insts, count) }
}

// ---------------------------------------------------------------------------
// Public API: hook / unhook
// ---------------------------------------------------------------------------

/// Inline-hook a function.
///
/// After calling `hook`, every invocation of `func` will be redirected to
/// `replace`. The original function can still be called via `backup`.
///
/// # Safety
///
/// `func` and `replace` must be valid function pointers.
pub unsafe fn hook(
    func: *const libc::c_void,
    replace: *const libc::c_void,
    backup: &mut *const libc::c_void,
) -> HookResult<()> {
    if func.is_null() || replace.is_null() {
        return Err(HookError::BadAddress);
    }

    let func_addr = func as usize;
    let origin_addr = resolve_branch(func_addr);

    // Allocate memory for the hook struct
    let hook_size = std::mem::size_of::<Hook>();
    let ptr = alloc::hook_mem_alloc(hook_size)?;
    let hook_ptr = ptr as *mut Hook;

    // Register it
    alloc::hook_mem_register(origin_addr, ptr)?;

    // Initialize
    unsafe {
        (*hook_ptr) = Hook {
            func_addr: func_addr as u64,
            origin_addr: origin_addr as u64,
            replace_addr: replace as u64,
            relo_addr: std::ptr::addr_of!((*hook_ptr).relo_insts) as u64,
            ..Default::default()
        };
    }

    // Set backup to the relocated code
    *backup = unsafe { std::ptr::addr_of!((*hook_ptr).relo_insts) } as *const libc::c_void;

    // Prepare and install
    let result = hook_prepare(unsafe { &mut *hook_ptr });
    if let Err(e) = result {
        alloc::hook_mem_unregister(origin_addr);
        alloc::hook_mem_free(ptr, hook_size);
        return Err(e);
    }

    hook_install(unsafe { &*hook_ptr })?;

    Ok(())
}

/// Remove a previously installed hook, restoring the original function.
///
/// # Safety
///
/// `func` must be the same pointer passed to `hook()`.
pub unsafe fn unhook(func: *const libc::c_void) {
    if func.is_null() {
        return;
    }
    let origin = resolve_branch(func as usize);

    if let Some(ptr) = alloc::hook_mem_lookup(origin) {
        let hook_ptr = ptr as *const Hook;

        let _ = hook_uninstall(unsafe { &*hook_ptr });
        alloc::hook_mem_unregister(origin);
        let hook_size = std::mem::size_of::<Hook>();
        alloc::hook_mem_free(ptr, hook_size);
    }
}
