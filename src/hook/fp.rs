//! Function-pointer hooking.
//!
//! Unlike inline hooks (which patch the first instructions of a function),
//! function-pointer hooks overwrite a **pointer variable** that holds a
//! function address. This is useful for hooking indirect calls through
//! vtables, callback registries, or hand-written function pointer tables.
//!
//! # How it works
//!
//! 1. Read the current function pointer at `*fp_addr`.
//! 2. Save it as `origin_fp` (the "backup").
//! 3. Write the replacement address (or transit trampoline for chains)
//!    to `*fp_addr`.
//!
//! For `fp_hook_wrap`, a chain with before/after callbacks is created
//! just like `hook_wrap`, but the original function is called through
//! the saved `origin_fp` pointer rather than a relocated instruction buffer.

use crate::error::{HookError, HookResult};
use crate::hook::context::*;
use crate::memory::alloc;

#[cfg(target_arch = "aarch64")]
use crate::instruction::decoder::{ARM64_BTI_JC, ARM64_NOP};

// ---------------------------------------------------------------------------
// FP transit dispatch functions (separate from inline transit)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn read_fp_chain_ptr() -> *mut FpHookChain {
    let chain: *mut FpHookChain;
    unsafe {
        std::arch::asm!("mov {0}, x16", out(reg) chain);
    }
    chain
}

/// FP transit for 0 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_fp_transit0() -> u64 {
    let chain_ptr = unsafe { read_fp_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs0 {
        chain: chain_ptr as *mut HookChain,
        skip_origin: 0,
        _pad: 0,
        local: HookLocal::default(),
        ret: 0,
    };

    for i in 0..chain.chain_items_max as usize {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain0Callback> = unsafe { std::mem::transmute(chain.befores[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    if fargs.skip_origin == 0 {
        let origin: unsafe extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(chain.hook.origin_fp as *const ()) };
        fargs.ret = unsafe { origin() };
    }

    for i in (0..chain.chain_items_max as usize).rev() {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain0Callback> = unsafe { std::mem::transmute(chain.afters[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    fargs.ret
}

/// FP transit for 1–4 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_fp_transit4(arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let chain_ptr = unsafe { read_fp_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs4 {
        chain: chain_ptr as *mut HookChain,
        skip_origin: 0,
        _pad: 0,
        local: HookLocal::default(),
        ret: 0,
        arg0,
        arg1,
        arg2,
        arg3,
    };

    for i in 0..chain.chain_items_max as usize {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain4Callback> = unsafe { std::mem::transmute(chain.befores[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    if fargs.skip_origin == 0 {
        let origin: unsafe extern "C" fn(u64, u64, u64, u64) -> u64 =
            unsafe { std::mem::transmute(chain.hook.origin_fp as *const ()) };
        fargs.ret = unsafe { origin(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3) };
    }

    for i in (0..chain.chain_items_max as usize).rev() {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain4Callback> = unsafe { std::mem::transmute(chain.afters[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    fargs.ret
}

/// FP transit for 5–8 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_fp_transit8(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    arg7: u64,
) -> u64 {
    let chain_ptr = unsafe { read_fp_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs8 {
        chain: chain_ptr as *mut HookChain,
        skip_origin: 0,
        _pad: 0,
        local: HookLocal::default(),
        ret: 0,
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6,
        arg7,
    };

    for i in 0..chain.chain_items_max as usize {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain8Callback> = unsafe { std::mem::transmute(chain.befores[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    if fargs.skip_origin == 0 {
        let origin: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
            unsafe { std::mem::transmute(chain.hook.origin_fp as *const ()) };
        fargs.ret = unsafe {
            origin(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                fargs.arg7,
            )
        };
    }

    for i in (0..chain.chain_items_max as usize).rev() {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain8Callback> = unsafe { std::mem::transmute(chain.afters[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    fargs.ret
}

/// FP transit for 9–12 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_fp_transit12(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    arg7: u64,
    arg8: u64,
    arg9: u64,
    arg10: u64,
    arg11: u64,
) -> u64 {
    let chain_ptr = unsafe { read_fp_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs12 {
        chain: chain_ptr as *mut HookChain,
        skip_origin: 0,
        _pad: 0,
        local: HookLocal::default(),
        ret: 0,
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6,
        arg7,
        arg8,
        arg9,
        arg10,
        arg11,
    };

    for i in 0..chain.chain_items_max as usize {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain12Callback> = unsafe { std::mem::transmute(chain.befores[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    if fargs.skip_origin == 0 {
        let origin: unsafe extern "C" fn(
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> u64 = unsafe { std::mem::transmute(chain.hook.origin_fp as *const ()) };
        fargs.ret = unsafe {
            origin(
                fargs.arg0,
                fargs.arg1,
                fargs.arg2,
                fargs.arg3,
                fargs.arg4,
                fargs.arg5,
                fargs.arg6,
                fargs.arg7,
                fargs.arg8,
                fargs.arg9,
                fargs.arg10,
                fargs.arg11,
            )
        };
    }

    for i in (0..chain.chain_items_max as usize).rev() {
        if chain.states[i] != CHAIN_ITEM_STATE_READY {
            continue;
        }
        let func: Option<HookChain12Callback> = unsafe { std::mem::transmute(chain.afters[i]) };
        if let Some(f) = func {
            unsafe { f(&mut fargs, chain.udata[i]) };
        }
    }

    fargs.ret
}

// ---------------------------------------------------------------------------
// FP transit function address lookup
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
fn fp_transit_func_for_argno(argno: i32) -> u64 {
    match argno {
        0 => _yuyu_fp_transit0 as *const () as u64,
        1..=4 => _yuyu_fp_transit4 as *const () as u64,
        5..=8 => _yuyu_fp_transit8 as *const () as u64,
        _ => _yuyu_fp_transit12 as *const () as u64,
    }
}

// ---------------------------------------------------------------------------
// FP trampoline header (same layout as inline, but for FpHookChain)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
fn fp_chain_prepare_transit(chain: *mut FpHookChain, argno: i32) -> HookResult<()> {
    let chain_ref = unsafe { &mut *chain };
    let transit = &mut chain_ref.transit;

    let transit_fn = fp_transit_func_for_argno(argno);

    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000070; // LDR X16, #12
    transit[2] = 0x580000D1; // LDR X17, #24
    transit[3] = 0xD61F0220; // BR X17
    transit[4] = (chain as u64) as u32;
    transit[5] = ((chain as u64) >> 32) as u32;
    transit[6] = ARM64_NOP;
    transit[7] = ARM64_NOP;
    transit[8] = transit_fn as u32;
    transit[9] = (transit_fn >> 32) as u32;

    for item in transit.iter_mut().skip(10) {
        *item = ARM64_NOP;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// FP chain management
// ---------------------------------------------------------------------------

fn fp_chain_add(
    chain: &mut FpHookChain,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    udata: *mut libc::c_void,
) -> HookResult<()> {
    for i in 0..FP_HOOK_CHAIN_NUM {
        if (!before.is_null() && chain.befores[i] == before)
            || (!after.is_null() && chain.afters[i] == after)
        {
            return Err(HookError::Duplicated);
        }

        if chain.states[i] == CHAIN_ITEM_STATE_EMPTY {
            chain.states[i] = CHAIN_ITEM_STATE_BUSY;
            unsafe { std::arch::asm!("dsb ish") };
            chain.udata[i] = udata;
            chain.befores[i] = before;
            chain.afters[i] = after;
            if (i + 1) as i32 > chain.chain_items_max {
                chain.chain_items_max = (i + 1) as i32;
            }
            unsafe { std::arch::asm!("dsb ish") };
            chain.states[i] = CHAIN_ITEM_STATE_READY;
            return Ok(());
        }
    }
    Err(HookError::ChainFull)
}

fn fp_chain_remove(chain: &mut FpHookChain, before: *mut libc::c_void, after: *mut libc::c_void) {
    for i in 0..FP_HOOK_CHAIN_NUM {
        if chain.states[i] == CHAIN_ITEM_STATE_READY
            && ((!before.is_null() && chain.befores[i] == before)
                || (!after.is_null() && chain.afters[i] == after))
        {
            chain.states[i] = CHAIN_ITEM_STATE_BUSY;
            unsafe { std::arch::asm!("dsb ish") };
            chain.udata[i] = std::ptr::null_mut();
            chain.befores[i] = std::ptr::null_mut();
            chain.afters[i] = std::ptr::null_mut();
            unsafe { std::arch::asm!("dsb ish") };
            chain.states[i] = CHAIN_ITEM_STATE_EMPTY;
            break;
        }
    }
}

fn fp_chain_is_empty(chain: &FpHookChain) -> bool {
    chain.states.iter().all(|&s| s == CHAIN_ITEM_STATE_EMPTY)
}

// ---------------------------------------------------------------------------
// Public API: fp_hook / fp_unhook
// ---------------------------------------------------------------------------

/// Hook a function pointer.
///
/// Overwrites the pointer at `fp_addr` with `replace`. The original pointer
/// value is saved to `backup`.
///
/// # Safety
///
/// `fp_addr` must point to a valid, writable function pointer variable.
/// `replace` must be a valid function pointer.
pub unsafe fn fp_hook(
    fp_addr: usize,
    replace: *const libc::c_void,
    backup: &mut *const libc::c_void,
) -> HookResult<()> {
    if fp_addr == 0 {
        return Err(HookError::BadAddress);
    }
    if replace.is_null() {
        return Err(HookError::BadAddress);
    }

    // Read original pointer
    let origin = unsafe { *(fp_addr as *const *const libc::c_void) };
    *backup = origin;

    // Write replacement
    unsafe {
        *(fp_addr as *mut *const libc::c_void) = replace;
    }

    Ok(())
}

/// Restore a function pointer hook.
///
/// Writes the original pointer value (from `backup`) back to `*fp_addr`.
///
/// # Safety
///
/// `fp_addr` must be the same address passed to `fp_hook`.
pub unsafe fn fp_unhook(fp_addr: usize, backup: *const libc::c_void) {
    if fp_addr == 0 || backup.is_null() {
        return;
    }
    unsafe {
        *(fp_addr as *mut *const libc::c_void) = backup;
    }
}

// ---------------------------------------------------------------------------
// Public API: fp_hook_wrap / fp_hook_unwrap
// ---------------------------------------------------------------------------

/// Wrap a function pointer with before/after callbacks.
///
/// Multiple wraps on the same pointer share a single chain.
///
/// # Safety
///
/// `fp_addr` must point to a valid, writable function pointer.
/// Callback signatures must match `argno`.
pub unsafe fn fp_hook_wrap(
    fp_addr: usize,
    argno: i32,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    udata: *mut libc::c_void,
) -> HookResult<()> {
    if fp_addr == 0 {
        return Err(HookError::BadAddress);
    }

    // Read current pointer value
    let origin_fp = unsafe { *(fp_addr as *const *const libc::c_void) } as u64;

    // Allocate chain
    let chain_size = std::mem::size_of::<FpHookChain>();
    let ptr = alloc::hook_mem_alloc(chain_size)?;
    let chain_ptr = ptr as *mut FpHookChain;

    // Initialize
    let chain = unsafe { &mut *chain_ptr };
    chain.chain_items_max = 0;
    for i in 0..FP_HOOK_CHAIN_NUM {
        chain.states[i] = CHAIN_ITEM_STATE_EMPTY;
        chain.udata[i] = std::ptr::null_mut();
        chain.befores[i] = std::ptr::null_mut();
        chain.afters[i] = std::ptr::null_mut();
    }
    chain.hook = FpHook {
        fp_addr,
        replace_addr: std::ptr::addr_of!(chain.transit) as u64,
        origin_fp,
    };

    // Register (use fp_addr as key, not origin_fp — multiple fp hooks
    // on the same address should share a chain)
    alloc::hook_mem_register(fp_addr, ptr)?;

    // Prepare transit trampoline
    #[cfg(target_arch = "aarch64")]
    {
        if let Err(e) = fp_chain_prepare_transit(chain_ptr, argno) {
            alloc::hook_mem_unregister(fp_addr);
            alloc::hook_mem_free(ptr, chain_size);
            return Err(e);
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        alloc::hook_mem_unregister(fp_addr);
        alloc::hook_mem_free(ptr, chain_size);
        return Err(HookError::BadRelo);
    }

    // Add first callback pair
    if let Err(e) = fp_chain_add(chain, before, after, udata) {
        alloc::hook_mem_unregister(fp_addr);
        alloc::hook_mem_free(ptr, chain_size);
        return Err(e);
    }

    // Write transit address to the function pointer variable
    unsafe {
        *(fp_addr as *mut *const libc::c_void) =
            std::ptr::addr_of!(chain.transit) as *const libc::c_void;
    }

    Ok(())
}

/// Remove callbacks and optionally free the chain if empty.
///
/// # Safety
///
/// `fp_addr` must be the same address passed to `fp_hook_wrap`.
pub unsafe fn fp_hook_unwrap(fp_addr: usize, before: *mut libc::c_void, after: *mut libc::c_void) {
    if fp_addr == 0 {
        return;
    }

    let ptr = match alloc::hook_mem_lookup(fp_addr) {
        Some(p) => p,
        None => return,
    };

    let chain = unsafe { &mut *(ptr as *mut FpHookChain) };
    fp_chain_remove(chain, before, after);

    if !fp_chain_is_empty(chain) {
        return;
    }

    // Restore original pointer and free
    unsafe {
        *(fp_addr as *mut *const libc::c_void) = chain.hook.origin_fp as *const libc::c_void;
    }
    alloc::hook_mem_unregister(fp_addr);
    let chain_size = std::mem::size_of::<FpHookChain>();
    alloc::hook_mem_free(ptr, chain_size);
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

macro_rules! define_fp_wrap {
    ($name:ident, $args:literal, $callback_ty:ty) => {
        /// Convenience wrapper for a specific argument count.
        ///
        /// # Safety
        ///
        /// `fp_addr` must point to a valid, writable function pointer.
        /// Callback signatures must match the original function's ABI.
        #[inline]
        pub unsafe fn $name(
            fp_addr: usize,
            before: $callback_ty,
            after: $callback_ty,
            udata: *mut libc::c_void,
        ) -> HookResult<()> {
            unsafe {
                fp_hook_wrap(
                    fp_addr,
                    $args,
                    before as *mut libc::c_void,
                    after as *mut libc::c_void,
                    udata,
                )
            }
        }
    };
}

define_fp_wrap!(fp_hook_wrap0, 0, HookChain0Callback);
define_fp_wrap!(fp_hook_wrap1, 1, HookChain1Callback);
define_fp_wrap!(fp_hook_wrap2, 2, HookChain2Callback);
define_fp_wrap!(fp_hook_wrap3, 3, HookChain3Callback);
define_fp_wrap!(fp_hook_wrap4, 4, HookChain4Callback);
define_fp_wrap!(fp_hook_wrap5, 5, HookChain5Callback);
define_fp_wrap!(fp_hook_wrap6, 6, HookChain6Callback);
define_fp_wrap!(fp_hook_wrap7, 7, HookChain7Callback);
define_fp_wrap!(fp_hook_wrap8, 8, HookChain8Callback);
define_fp_wrap!(fp_hook_wrap9, 9, HookChain9Callback);
define_fp_wrap!(fp_hook_wrap10, 10, HookChain10Callback);
define_fp_wrap!(fp_hook_wrap11, 11, HookChain11Callback);
define_fp_wrap!(fp_hook_wrap12, 12, HookChain12Callback);
