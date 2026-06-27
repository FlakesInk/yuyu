//! Hook context types for inline hook chains.
//!
//! Defines the argument-passing structures (`hook_fargs*_t`) and chain
//! management structures (`hook_chain_t`) used by the hook wrap API.
//!
//! ## Memory Layout
//!
//! The `HookChain` struct is allocated in executable memory. Its `relo_insts`
//! array is placed at the end so that `relo_addr` can point directly into
//! the struct — the caller's "backup" function pointer executes code stored
//! inline within the chain allocation.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of trampoline instructions.
pub const TRAMPOLINE_MAX_NUM: usize = 6;
/// Number of relocated instruction slots.
pub const RELOCATE_INST_NUM: usize = 36; // (4*8 + 8 - 4)
/// Maximum number of chain callbacks.
pub const HOOK_CHAIN_NUM: usize = 0x10;
/// Transit buffer size in u32 words.
pub const TRANSIT_INST_NUM: usize = 0x60;
/// Maximum number of function-pointer chain callbacks.
pub const FP_HOOK_CHAIN_NUM: usize = 0x20;
/// Number of local data slots in hook_fargs.
pub const HOOK_LOCAL_DATA_NUM: usize = 8;

/// Chain item states.
pub const CHAIN_ITEM_STATE_EMPTY: i8 = 0;
pub const CHAIN_ITEM_STATE_READY: i8 = 1;
pub const CHAIN_ITEM_STATE_BUSY: i8 = 2;

// ---------------------------------------------------------------------------
// Hook argument structures (matching C ABI layouts)
// ---------------------------------------------------------------------------

/// Local data that hook callbacks can use to pass state between before/after.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookLocal {
    pub data: [u64; HOOK_LOCAL_DATA_NUM],
}

impl Default for HookLocal {
    fn default() -> Self {
        Self {
            data: [0u64; HOOK_LOCAL_DATA_NUM],
        }
    }
}

/// Base hook arguments (0 register arguments).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookFargs0 {
    /// Pointer back to the `HookChain`.
    pub chain: *mut HookChain,
    /// Set to non-zero to skip calling the original function.
    pub skip_origin: i32,
    /// Padding for alignment.
    pub _pad: i32,
    /// Scratch data for use between before/after callbacks.
    pub local: HookLocal,
    /// Return value (set by original function or after callback).
    pub ret: u64,
}

/// Hook arguments for 1–4 register arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookFargs4 {
    pub chain: *mut HookChain,
    pub skip_origin: i32,
    pub _pad: i32,
    pub local: HookLocal,
    pub ret: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
}

/// Hook arguments for 5–8 register arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookFargs8 {
    pub chain: *mut HookChain,
    pub skip_origin: i32,
    pub _pad: i32,
    pub local: HookLocal,
    pub ret: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
    pub arg7: u64,
}

/// Hook arguments for 9–12 register arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookFargs12 {
    pub chain: *mut HookChain,
    pub skip_origin: i32,
    pub _pad: i32,
    pub local: HookLocal,
    pub ret: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
    pub arg7: u64,
    pub arg8: u64,
    pub arg9: u64,
    pub arg10: u64,
    pub arg11: u64,
}

// Type aliases for individual argument counts.
pub type HookFargs1 = HookFargs4;
pub type HookFargs2 = HookFargs4;
pub type HookFargs3 = HookFargs4;
pub type HookFargs5 = HookFargs8;
pub type HookFargs6 = HookFargs8;
pub type HookFargs7 = HookFargs8;
pub type HookFargs9 = HookFargs12;
pub type HookFargs10 = HookFargs12;
pub type HookFargs11 = HookFargs12;

// ---------------------------------------------------------------------------
// Callback types
// ---------------------------------------------------------------------------

pub type HookChain0Callback = unsafe extern "C" fn(*mut HookFargs0, *mut libc::c_void);
pub type HookChain1Callback = unsafe extern "C" fn(*mut HookFargs1, *mut libc::c_void);
pub type HookChain2Callback = unsafe extern "C" fn(*mut HookFargs2, *mut libc::c_void);
pub type HookChain3Callback = unsafe extern "C" fn(*mut HookFargs3, *mut libc::c_void);
pub type HookChain4Callback = unsafe extern "C" fn(*mut HookFargs4, *mut libc::c_void);
pub type HookChain5Callback = unsafe extern "C" fn(*mut HookFargs5, *mut libc::c_void);
pub type HookChain6Callback = unsafe extern "C" fn(*mut HookFargs6, *mut libc::c_void);
pub type HookChain7Callback = unsafe extern "C" fn(*mut HookFargs7, *mut libc::c_void);
pub type HookChain8Callback = unsafe extern "C" fn(*mut HookFargs8, *mut libc::c_void);
pub type HookChain9Callback = unsafe extern "C" fn(*mut HookFargs9, *mut libc::c_void);
pub type HookChain10Callback = unsafe extern "C" fn(*mut HookFargs10, *mut libc::c_void);
pub type HookChain11Callback = unsafe extern "C" fn(*mut HookFargs11, *mut libc::c_void);
pub type HookChain12Callback = unsafe extern "C" fn(*mut HookFargs12, *mut libc::c_void);

// ---------------------------------------------------------------------------
// HookChain — the core structure combining hook trampoline + chain state
// ---------------------------------------------------------------------------

/// An inline hook chain.
///
/// This structure is allocated in executable memory. The relocated
/// instruction buffer lives at the end of the struct, so the `relo_addr`
/// field in the embedded `Hook` points directly into this allocation.
#[repr(C, align(8))]
pub struct HookChain {
    /// The low-level hook (must be first to match C layout).
    pub hook: Hook,

    /// Number of active chain items (max index + 1).
    pub chain_items_max: i32,

    /// Per-slot state: EMPTY, READY, or BUSY.
    pub states: [i8; HOOK_CHAIN_NUM],

    /// Private padding for alignment.
    pub _pad: [u8; 3],

    /// User data pointers for each chain slot.
    pub udata: [*mut libc::c_void; HOOK_CHAIN_NUM],

    /// Before-callback function pointers (one per slot).
    pub befores: [*mut libc::c_void; HOOK_CHAIN_NUM],

    /// After-callback function pointers (one per slot).
    pub afters: [*mut libc::c_void; HOOK_CHAIN_NUM],

    /// Transit trampoline code (the entry point that replaces the original
    /// function, dispatches to callbacks, and calls the relocated original).
    pub transit: [u32; TRANSIT_INST_NUM],
}

/// The low-level inline hook descriptor.
///
/// ## Field roles
/// - `func_addr`: the user-supplied function pointer (may point to a branch).
/// - `origin_addr`: the resolved first real instruction address.
/// - `replace_addr`: the trampoline/transit entry point.
/// - `relo_addr`: pointer to the relocated instruction buffer (inside this struct).
/// - `origin_insts`: backup of original instructions.
/// - `tramp_insts`: trampoline instructions that overwrite `origin_addr`.
/// - `relo_insts`: relocated versions of `origin_insts`, followed by a jump-back.
/// - `tramp_insts_num`: number of u32 words in the trampoline.
/// - `relo_insts_num`: number of u32 words in the relocated buffer.
#[repr(C, align(8))]
pub struct Hook {
    pub func_addr: u64,
    pub origin_addr: u64,
    pub replace_addr: u64,
    pub relo_addr: u64,
    pub tramp_insts_num: i32,
    pub relo_insts_num: i32,
    pub origin_insts: [u32; TRAMPOLINE_MAX_NUM],
    pub tramp_insts: [u32; TRAMPOLINE_MAX_NUM],
    pub relo_insts: [u32; RELOCATE_INST_NUM],
}

impl Default for Hook {
    fn default() -> Self {
        Self {
            func_addr: 0,
            origin_addr: 0,
            replace_addr: 0,
            relo_addr: 0,
            tramp_insts_num: 0,
            relo_insts_num: 0,
            origin_insts: [0; TRAMPOLINE_MAX_NUM],
            tramp_insts: [0; TRAMPOLINE_MAX_NUM],
            relo_insts: [0; RELOCATE_INST_NUM],
        }
    }
}

// ---------------------------------------------------------------------------
// Function-pointer hook types
// ---------------------------------------------------------------------------

/// A function-pointer hook descriptor.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct FpHook {
    pub fp_addr: usize,
    pub replace_addr: u64,
    pub origin_fp: u64,
}

/// A function-pointer hook chain.
#[repr(C, align(8))]
pub struct FpHookChain {
    pub hook: FpHook,
    pub chain_items_max: i32,
    pub _pad: [u8; 4],
    pub states: [i8; FP_HOOK_CHAIN_NUM],
    pub _pad2: [u8; 3],
    pub udata: [*mut libc::c_void; FP_HOOK_CHAIN_NUM],
    pub befores: [*mut libc::c_void; FP_HOOK_CHAIN_NUM],
    pub afters: [*mut libc::c_void; FP_HOOK_CHAIN_NUM],
    pub transit: [u32; TRANSIT_INST_NUM],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the original function pointer from hook arguments.
///
/// This can be called from within a before/after callback to invoke the
/// original (unhooked) function.
///
/// # Safety
///
/// `hook_args` must be a valid pointer to a `HookFargs0` passed by the
/// transit dispatcher. Calling this outside of a hook callback is UB.
pub unsafe fn wrap_get_origin_func(hook_args: *mut HookFargs0) -> *mut libc::c_void {
    let args = unsafe { &*hook_args };
    let chain = unsafe { &*(args.chain) };
    chain.hook.relo_addr as *mut libc::c_void
}

/// Get the original function pointer from a function-pointer hook.
///
/// # Safety
///
/// `hook_args` must be a valid pointer to a `HookFargs0` from a
/// function-pointer hook callback.
pub unsafe fn fp_get_origin_func(hook_args: *mut HookFargs0) -> *mut libc::c_void {
    let args = unsafe { &*hook_args };
    let chain = args.chain as *const FpHookChain;
    unsafe { (*chain).hook.origin_fp as *mut libc::c_void }
}
