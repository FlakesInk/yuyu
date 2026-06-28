//! Transit dispatch functions for hook chains.
//!
//! When a hooked function is called, execution enters `chain.transit` — a
//! small trampoline header that loads the chain pointer into X16 and the
//! appropriate transit function address into X17, then branches to X17.
//!
//! The transit function has the **same signature** as the original function,
//! so the original arguments arrive in X0–X7 (and stack) exactly as the
//! original caller left them. It reads X16 at entry (before the compiler-
//! generated prologue can clobber it — X16 / IP0 is not used in standard
//! aarch64 prologues) and uses it to find the chain.
//!
//! Public chain management (`hook_wrap`, `hook_chain_add`, etc.) lives in
//! [`super::chain`].

use crate::error::HookResult;
use crate::hook::context::*;
use crate::instruction::decoder::{ARM64_BTI_JC, ARM64_NOP};

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
pub(crate) fn hook_chain_prepare_transit(chain: *mut HookChain, argno: i32) -> HookResult<()> {
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
