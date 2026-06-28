//! Trampoline and hook-chain management.
//!
//! Implements `hook_wrap`, `hook_chain_add`, `hook_chain_remove`,
//! `hook_unwrap`, and the transit dispatch functions that call
//! before/after callbacks around the original function.
//!
//! ## How transit works
//!
//! The trampoline header (written into `chain->transit`) loads the chain
//! pointer into X16 and the appropriate transit function address into X17,
//! then branches to X17. The transit function reads X16 at entry (before
//! the compiler-generated prologue can clobber it — X16/IP0 is not used
//! in standard aarch64 prologues) and uses it to find the chain.
//!
//! The transit function has the **same signature** as the original function,
//! so the original arguments arrive in X0–X7 (and stack) exactly as the
//! original caller left them.

use crate::error::{HookError, HookResult};
use crate::hook::context::*;
use crate::hook::inline;
use crate::hook::patch::resolve_branch;
use crate::instruction::decoder::{ARM64_BTI_JC, ARM64_NOP};
use crate::memory::alloc;
use crate::utils;

// ---------------------------------------------------------------------------
// Helpers: read chain pointer from X16
// ---------------------------------------------------------------------------

/// Read the chain pointer that was loaded into X16 by the trampoline header.
///
/// Must be called at the very beginning of a transit function, before any
/// other code that might clobber X16. On aarch64, X16 (IP0) is a scratch
/// register that the compiler avoids using in function prologues.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn read_chain_ptr() -> *mut HookChain {
    let chain: *mut HookChain;
    unsafe {
        std::arch::asm!("mov {0}, x16", out(reg) chain);
    }
    chain
}

// ---------------------------------------------------------------------------
// Transit dispatch functions — one per argument-count group
// ---------------------------------------------------------------------------
//
// Each function:
// 1. Reads the chain pointer from X16 at entry.
// 2. Builds a HookFargs struct with the original arguments.
// 3. Calls before callbacks (forward order).
// 4. Calls the relocated original function (if not skipped).
// 5. Calls after callbacks (reverse order).
// 6. Returns the result in X0.

/// Transit for 0 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_transit0() -> u64 {
    let chain_ptr = unsafe { read_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs0 {
        chain: chain_ptr,
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
            unsafe { std::mem::transmute(chain.hook.relo_addr as *const ()) };
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

/// Transit for 1–4 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_transit4(arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let chain_ptr = unsafe { read_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs4 {
        chain: chain_ptr,
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
            unsafe { std::mem::transmute(chain.hook.relo_addr as *const ()) };
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

/// Transit for 5–8 register arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_transit8(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    arg7: u64,
) -> u64 {
    let chain_ptr = unsafe { read_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs8 {
        chain: chain_ptr,
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
            unsafe { std::mem::transmute(chain.hook.relo_addr as *const ()) };
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

/// Transit for 9–12 register arguments.
///
/// Note: On aarch64, arguments beyond 8 are passed on the stack. The
/// transit header does not reposition stack arguments, so arg8–arg11
/// correspond to the original caller's stack slots for the 9th–12th
/// arguments.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn _yuyu_transit12(
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
    let chain_ptr = unsafe { read_chain_ptr() };
    if chain_ptr.is_null() {
        return 0;
    }
    let chain = unsafe { &mut *chain_ptr };

    let mut fargs = HookFargs12 {
        chain: chain_ptr,
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
        ) -> u64 = unsafe { std::mem::transmute(chain.hook.relo_addr as *const ()) };
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
// Get transit function address by argument count
// ---------------------------------------------------------------------------

/// Return the address of the appropriate transit function for `argno`.
fn transit_func_for_argno(argno: i32) -> u64 {
    match argno {
        0 => _yuyu_transit0 as *const () as u64,
        1..=4 => _yuyu_transit4 as *const () as u64,
        5..=8 => _yuyu_transit8 as *const () as u64,
        _ => _yuyu_transit12 as *const () as u64,
    }
}

// ---------------------------------------------------------------------------
// Trampoline header generation
// ---------------------------------------------------------------------------

/// Build the trampoline header in `chain->transit`.
///
/// Layout (indices into u32 array):
/// ```text
/// [0]  BTI_JC             (0xD503249F)
/// [1]  LDR X16, #12       (0x58000060) → loads chain ptr from [4:5]
/// [2]  LDR X17, #24       (0x580000D1) → loads transit fn from [8:9]
/// [3]  BR X17             (0xD61F0220)
/// [4]  chain_lo           (.quad)
/// [5]  chain_hi
/// [6]  NOP                (padding)
/// [7]  NOP                (padding)
/// [8]  transit_fn_lo      (.quad)
/// [9]  transit_fn_hi
/// ```
#[cfg(target_arch = "aarch64")]
#[inline(never)]
fn hook_chain_prepare_transit(chain: *mut HookChain, argno: i32) -> HookResult<()> {
    let chain_ref = unsafe { &mut *chain };
    let transit = &mut chain_ref.transit;

    let transit_fn = transit_func_for_argno(argno);

    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000070; // LDR X16, #12  (load from +12 → transit[4:5])
    transit[2] = 0x580000D1; // LDR X17, #24  (load from +24 → transit[8:9])
    transit[3] = 0xD61F0220; // BR X17
    transit[4] = (chain as u64) as u32;
    transit[5] = ((chain as u64) >> 32) as u32;
    transit[6] = ARM64_NOP;
    transit[7] = ARM64_NOP;
    transit[8] = transit_fn as u32;
    transit[9] = (transit_fn >> 32) as u32;

    // Fill remaining transit buffer with NOPs
    for item in transit.iter_mut().skip(10) {
        *item = ARM64_NOP;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Chain management
// ---------------------------------------------------------------------------

/// Add a before/after callback pair to an existing hook chain.
pub fn hook_chain_add(
    chain: &mut HookChain,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    udata: *mut libc::c_void,
) -> HookResult<()> {
    for i in 0..HOOK_CHAIN_NUM {
        if (!before.is_null() && chain.befores[i] == before)
            || (!after.is_null() && chain.afters[i] == after)
        {
            return Err(HookError::Duplicated);
        }

        if chain.states[i] == CHAIN_ITEM_STATE_EMPTY {
            chain.states[i] = CHAIN_ITEM_STATE_BUSY;

            // Memory barrier
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

/// Remove a before/after callback pair from a hook chain.
pub fn hook_chain_remove(
    chain: &mut HookChain,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
) {
    for i in 0..HOOK_CHAIN_NUM {
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

/// Return true if all chain slots are empty.
pub fn hook_chain_is_empty(chain: &HookChain) -> bool {
    chain.states.iter().all(|&s| s == CHAIN_ITEM_STATE_EMPTY)
}

// ---------------------------------------------------------------------------
// Public API: hook_wrap / hook_unwrap
// ---------------------------------------------------------------------------

/// Wrap a function with before and after callbacks.
///
/// Multiple wraps on the same function share a single chain. `argno` is the
/// number of register arguments (0–12).
///
/// # Safety
///
/// `func` must be a valid function pointer. `before`/`after` may be null.
/// Callback signatures must match `argno` (see `HookChain*Callback` types).
pub unsafe fn hook_wrap(
    func: *const libc::c_void,
    argno: i32,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    udata: *mut libc::c_void,
) -> HookResult<()> {
    if func.is_null() {
        return Err(HookError::BadAddress);
    }

    let faddr = func as usize;
    let origin = resolve_branch(faddr);

    utils::check_func_addr(origin)?;

    // If a chain already exists for this function, just add our callbacks
    if let Some(ptr) = alloc::hook_mem_lookup(origin) {
        let chain = unsafe { &mut *(ptr as *mut HookChain) };
        return hook_chain_add(chain, before, after, udata);
    }

    // Allocate a new chain
    let chain_size = std::mem::size_of::<HookChain>();
    let ptr = alloc::hook_mem_alloc(chain_size)?;
    let chain_ptr = ptr as *mut HookChain;

    // Initialize chain
    let chain = unsafe { &mut *chain_ptr };
    chain.chain_items_max = 0;
    for i in 0..HOOK_CHAIN_NUM {
        chain.states[i] = CHAIN_ITEM_STATE_EMPTY;
        chain.udata[i] = std::ptr::null_mut();
        chain.befores[i] = std::ptr::null_mut();
        chain.afters[i] = std::ptr::null_mut();
    }

    // Initialize embedded hook
    chain.hook = Hook {
        func_addr: faddr as u64,
        origin_addr: origin as u64,
        replace_addr: std::ptr::addr_of!(chain.transit) as u64,
        relo_addr: std::ptr::addr_of!(chain.hook.relo_insts) as u64,
        ..Default::default()
    };

    // Register before prepare
    alloc::hook_mem_register(origin, ptr)?;

    // Prepare the inline hook
    if let Err(e) = inline::hook_prepare(&mut chain.hook) {
        alloc::hook_mem_unregister(origin);
        alloc::hook_mem_free(ptr, chain_size);
        return Err(e);
    }

    // Prepare the transit trampoline header
    #[cfg(target_arch = "aarch64")]
    {
        if let Err(e) = hook_chain_prepare_transit(chain_ptr, argno) {
            alloc::hook_mem_unregister(origin);
            alloc::hook_mem_free(ptr, chain_size);
            return Err(e);
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        alloc::hook_mem_unregister(origin);
        alloc::hook_mem_free(ptr, chain_size);
        return Err(HookError::BadRelo);
    }

    // Add the first callback pair
    if let Err(e) = hook_chain_add(chain, before, after, udata) {
        alloc::hook_mem_unregister(origin);
        alloc::hook_mem_free(ptr, chain_size);
        return Err(e);
    }

    // Install — patches original code with jump to transit
    inline::hook_install(&chain.hook)?;

    Ok(())
}

/// Remove callbacks and optionally free the chain if empty.
///
/// # Safety
///
/// `func` must be the same pointer passed to `hook_wrap`.
pub unsafe fn hook_unwrap_remove(
    func: *const libc::c_void,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    remove: bool,
) {
    if func.is_null() {
        return;
    }

    let faddr = func as usize;
    let origin = resolve_branch(faddr);

    if utils::is_bad_address(origin) {
        return;
    }

    let ptr = match alloc::hook_mem_lookup(origin) {
        Some(p) => p,
        None => return,
    };

    let chain = unsafe { &mut *(ptr as *mut HookChain) };
    hook_chain_remove(chain, before, after);

    if !remove || !hook_chain_is_empty(chain) {
        return;
    }

    // Chain is empty — uninstall and free
    let _ = inline::hook_uninstall(&chain.hook);
    alloc::hook_mem_unregister(origin);
    let chain_size = std::mem::size_of::<HookChain>();
    alloc::hook_mem_free(ptr, chain_size);
}

/// Install a prepared hook chain (patches the original code).
pub fn hook_chain_install(chain: &HookChain) -> HookResult<()> {
    inline::hook_install(&chain.hook)
}

/// Uninstall a hook chain (restores the original code).
pub fn hook_chain_uninstall(chain: &HookChain) -> HookResult<()> {
    inline::hook_uninstall(&chain.hook)
}

/// Convenience: unwrap and remove.
///
/// # Safety
///
/// `func` must be the same pointer passed to `hook_wrap`. `before`/`after`
/// must match the callbacks previously registered.
#[inline]
pub unsafe fn hook_unwrap(
    func: *const libc::c_void,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
) {
    unsafe { hook_unwrap_remove(func, before, after, true) }
}

// ---------------------------------------------------------------------------
// Typed convenience wrappers (hook_wrap0 through hook_wrap12)
// ---------------------------------------------------------------------------

macro_rules! define_wrap {
    ($name:ident, $args:literal, $callback_ty:ty) => {
        /// Convenience wrapper for a specific argument count.
        ///
        /// # Safety
        ///
        /// `func` must be a valid function pointer. The callback signatures
        /// must match the original function's ABI (see `HookChain*Callback` types).
        #[inline]
        pub unsafe fn $name(
            func: *const libc::c_void,
            before: $callback_ty,
            after: $callback_ty,
            udata: *mut libc::c_void,
        ) -> HookResult<()> {
            unsafe {
                hook_wrap(
                    func,
                    $args,
                    before as *mut libc::c_void,
                    after as *mut libc::c_void,
                    udata,
                )
            }
        }
    };
}

define_wrap!(hook_wrap0, 0, HookChain0Callback);
define_wrap!(hook_wrap1, 1, HookChain1Callback);
define_wrap!(hook_wrap2, 2, HookChain2Callback);
define_wrap!(hook_wrap3, 3, HookChain3Callback);
define_wrap!(hook_wrap4, 4, HookChain4Callback);
define_wrap!(hook_wrap5, 5, HookChain5Callback);
define_wrap!(hook_wrap6, 6, HookChain6Callback);
define_wrap!(hook_wrap7, 7, HookChain7Callback);
define_wrap!(hook_wrap8, 8, HookChain8Callback);
define_wrap!(hook_wrap9, 9, HookChain9Callback);
define_wrap!(hook_wrap10, 10, HookChain10Callback);
define_wrap!(hook_wrap11, 11, HookChain11Callback);
define_wrap!(hook_wrap12, 12, HookChain12Callback);
