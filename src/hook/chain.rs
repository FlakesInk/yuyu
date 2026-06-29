//! Hook chain management and wrap / unwrap API.
//!
//! ## Two API layers
//!
//! | Layer | Example | When to use |
//! |-------|---------|-------------|
//! | **Free functions** | `hook_wrap()`, `hook_chain_add()`, `hook_unwrap()` | Quick one-liners, C-FFI |
//! | **`Chain` object** | `Chain::wrap()`, `chain.add()`, `chain.remove()` | Owned lifecycle, hot-reload |
//!
//! ## Node identifiers
//!
//! Every callback added to a chain gets a [`ChainNodeId`] token. The token
//! (not the raw function pointer) is what you use to remove or hot-reload a
//! node. Tokens embed a per-slot generation counter so a stale token from a
//! previously-removed slot is **always rejected** — you can never accidentally
//! remove the wrong callback.
//!
//! ## Hot-reload
//!
//! Call [`Chain::reload`] to atomically swap the before / after callbacks
//! (and user data) for an existing node without tearing down the chain.
//! This is safe to do while the hooked function may be executing on another
//! core — the transition uses the same BUSY → READY state machine as `add`.

use crate::error::{HookError, HookResult};
use crate::hook::context::*;
use crate::hook::inline;
use crate::hook::patch::resolve_branch;
use crate::hook::trampoline::hook_chain_prepare_transit;
use crate::memory::alloc;
use crate::utils;

// ---------------------------------------------------------------------------
// Chain slot management (token-based)
// ---------------------------------------------------------------------------

/// Add a before / after callback pair to a hook chain.
///
/// Returns a [`ChainNodeId`] token. Save this token — you'll need it to
/// remove or hot-reload the node later. `before` and `after` may be null.
pub fn hook_chain_add(
    chain: &mut HookChain,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    udata: *mut libc::c_void,
) -> HookResult<ChainNodeId> {
    for i in 0..HOOK_CHAIN_NUM {
        if chain.states[i] == CHAIN_ITEM_STATE_EMPTY {
            chain.states[i] = CHAIN_ITEM_STATE_BUSY;

            // Memory barrier — ensure state write is visible before data writes
            unsafe { std::arch::asm!("dsb ish") };

            chain.udata[i] = udata;
            chain.befores[i] = before;
            chain.afters[i] = after;

            if (i + 1) as i32 > chain.chain_items_max {
                chain.chain_items_max = (i + 1) as i32;
            }

            let generation = chain.slot_generations[i];

            // Memory barrier — ensure data writes are visible before state flip
            unsafe { std::arch::asm!("dsb ish") };
            chain.states[i] = CHAIN_ITEM_STATE_READY;

            return Ok(ChainNodeId {
                index: i as u8,
                generation,
            });
        }
    }
    Err(HookError::ChainFull)
}

/// Remove a callback from a hook chain by [`ChainNodeId`].
///
/// The token must have been returned by a prior [`hook_chain_add`] call on
/// the **same** chain. If the token's generation doesn't match (because the
/// slot was already removed and recycled), the call is silently ignored.
pub fn hook_chain_remove(chain: &mut HookChain, node: ChainNodeId) {
    let i = node.index as usize;
    if i >= HOOK_CHAIN_NUM {
        return;
    }
    if chain.slot_generations[i] != node.generation {
        return;
    }
    if chain.states[i] != CHAIN_ITEM_STATE_READY {
        return;
    }

    chain.states[i] = CHAIN_ITEM_STATE_BUSY;
    unsafe { std::arch::asm!("dsb ish") };
    chain.udata[i] = std::ptr::null_mut();
    chain.befores[i] = std::ptr::null_mut();
    chain.afters[i] = std::ptr::null_mut();

    // Bump generation so stale tokens are rejected
    chain.slot_generations[i] = chain.slot_generations[i].wrapping_add(1);

    unsafe { std::arch::asm!("dsb ish") };
    chain.states[i] = CHAIN_ITEM_STATE_EMPTY;
}

/// Hot-reload a callback node — atomically swap `before`, `after`, and
/// `udata` for the slot identified by `node`.
///
/// This is safe to call while the hooked function may be executing. The
/// transition goes through the BUSY state so the transit dispatcher will
/// skip the slot during the swap window.
///
/// # Errors
///
/// Returns [`HookError::BadAddress`] if the token's generation doesn't
/// match (stale / already-removed token).
pub fn hook_chain_reload(
    chain: &mut HookChain,
    node: ChainNodeId,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
    udata: *mut libc::c_void,
) -> HookResult<()> {
    let i = node.index as usize;
    if i >= HOOK_CHAIN_NUM {
        return Err(HookError::BadAddress);
    }
    if chain.slot_generations[i] != node.generation {
        return Err(HookError::BadAddress);
    }
    if chain.states[i] != CHAIN_ITEM_STATE_READY {
        return Err(HookError::BadAddress);
    }

    chain.states[i] = CHAIN_ITEM_STATE_BUSY;
    unsafe { std::arch::asm!("dsb ish") };
    chain.udata[i] = udata;
    chain.befores[i] = before;
    chain.afters[i] = after;
    unsafe { std::arch::asm!("dsb ish") };
    chain.states[i] = CHAIN_ITEM_STATE_READY;

    Ok(())
}

/// Return `true` if every chain slot is in the `EMPTY` state.
pub fn hook_chain_is_empty(chain: &HookChain) -> bool {
    chain.states.iter().all(|&s| s == CHAIN_ITEM_STATE_EMPTY)
}

/// Install a prepared hook chain by patching the original code.
pub fn hook_chain_install(chain: &HookChain) -> HookResult<()> {
    inline::hook_install(&chain.hook)
}

/// Uninstall a hook chain, restoring the original instructions.
pub fn hook_chain_uninstall(chain: &HookChain) -> HookResult<()> {
    inline::hook_uninstall(&chain.hook)
}

// ---------------------------------------------------------------------------
// Chain — owned wrapper with OO API
// ---------------------------------------------------------------------------

/// An owned, managed hook chain.
///
/// Created by [`Chain::wrap`]. Provides `add`, `remove`, `reload`, and
/// auto-cleanup on drop.
///
/// # Example
///
/// ```rust,no_run
/// # use yuyu::hook::{Chain, ChainNodeId, HookFargs2};
/// # use std::ffi::c_void;
/// # extern "C" fn my_func(a: u64, b: u64) -> u64 { a + b }
/// # unsafe extern "C" fn before(f: *mut HookFargs2, _: *mut c_void) {}
/// # unsafe extern "C" fn after(f: *mut HookFargs2, _: *mut c_void) {}
/// unsafe {
///     let (mut chain, _node1) = Chain::wrap(
///         my_func as *const c_void, 2,
///         before as *mut c_void, after as *mut c_void,
///         std::ptr::null_mut(),
///     ).expect("wrap failed");
///
///     // Add another callback pair
///     let node2 = chain.add(
///         before as *mut c_void, after as *mut c_void,
///         std::ptr::null_mut(),
///     ).expect("add failed");
///
///     // Hot-reload node2
///     chain.reload(node2,
///         before as *mut c_void, after as *mut c_void,
///         std::ptr::null_mut(),
///     ).expect("reload failed");
///
///     // Remove node2
///     chain.remove(node2);
///
///     // Chain auto-uninstalls when dropped
/// }
/// ```
pub struct Chain {
    /// Pointer to the `HookChain` allocation in executable memory.
    inner: *mut HookChain,
    /// Whether we own the allocation (and should uninstall + free on drop).
    owned: bool,
}

impl Chain {
    /// Create a new hook chain, install it, and add the first callback pair.
    ///
    /// `argno` is the count of register arguments (0–12). Returns the owned
    /// `Chain` (auto-uninstalls on drop) and the [`ChainNodeId`] token for
    /// the first callback.
    ///
    /// # Safety
    ///
    /// Same requirements as [`hook_wrap`].
    pub unsafe fn wrap(
        func: *const libc::c_void,
        argno: i32,
        before: *mut libc::c_void,
        after: *mut libc::c_void,
        udata: *mut libc::c_void,
    ) -> HookResult<(Self, ChainNodeId)> {
        if func.is_null() {
            return Err(HookError::BadAddress);
        }

        let faddr = func as usize;
        let origin = resolve_branch(faddr);
        utils::check_func_addr(origin)?;

        // Allocate and initialise a new chain
        let chain_size = std::mem::size_of::<HookChain>();
        let ptr = alloc::hook_mem_alloc(chain_size)?;
        let chain_ptr = ptr as *mut HookChain;

        let chain = unsafe { &mut *chain_ptr };
        chain.chain_items_max = 0;
        for i in 0..HOOK_CHAIN_NUM {
            chain.states[i] = CHAIN_ITEM_STATE_EMPTY;
            chain.slot_generations[i] = 0;
            chain.udata[i] = std::ptr::null_mut();
            chain.befores[i] = std::ptr::null_mut();
            chain.afters[i] = std::ptr::null_mut();
        }

        chain.hook = Hook {
            func_addr: faddr as u64,
            origin_addr: origin as u64,
            replace_addr: std::ptr::addr_of!(chain.transit) as u64,
            relo_addr: std::ptr::addr_of!(chain.hook.relo_insts) as u64,
            ..Default::default()
        };

        alloc::hook_mem_register(origin, ptr)?;

        // Prepare
        if let Err(e) = inline::hook_prepare(&mut chain.hook) {
            alloc::hook_mem_unregister(origin);
            alloc::hook_mem_free(ptr, chain_size);
            return Err(e);
        }

        {
            if let Err(e) = hook_chain_prepare_transit(chain_ptr, argno) {
                alloc::hook_mem_unregister(origin);
                alloc::hook_mem_free(ptr, chain_size);
                return Err(e);
            }
        }

        // First callback
        let node = hook_chain_add(chain, before, after, udata)?;
        inline::hook_install(&chain.hook)?;

        Ok((
            Chain {
                inner: chain_ptr,
                owned: true,
            },
            node,
        ))
    }

    // -- internal: borrow an existing chain from the global registry ----------

    /// Create a non-owning handle from a raw `HookChain` pointer.
    ///
    /// Used internally when `hook_wrap` finds an existing chain in the
    /// registry. The returned `Chain` will **not** uninstall or free on drop.
    pub(crate) unsafe fn from_raw(ptr: *mut HookChain) -> Self {
        Chain {
            inner: ptr,
            owned: false,
        }
    }

    // -- public methods -------------------------------------------------------

    /// Add a before / after callback pair.
    ///
    /// Returns a [`ChainNodeId`] token. Use it with [`remove`](Self::remove)
    /// or [`reload`](Self::reload).
    pub fn add(
        &mut self,
        before: *mut libc::c_void,
        after: *mut libc::c_void,
        udata: *mut libc::c_void,
    ) -> HookResult<ChainNodeId> {
        let chain = unsafe { &mut *self.inner };
        hook_chain_add(chain, before, after, udata)
    }

    /// Remove a callback by its [`ChainNodeId`] token.
    ///
    /// If the token is stale (generation mismatch), the call is silently
    /// ignored.
    pub fn remove(&mut self, node: ChainNodeId) {
        let chain = unsafe { &mut *self.inner };
        hook_chain_remove(chain, node);
    }

    /// Hot-reload: atomically replace `before`, `after`, and `udata` for
    /// the node identified by `node`.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is stale (already removed).
    pub fn reload(
        &mut self,
        node: ChainNodeId,
        before: *mut libc::c_void,
        after: *mut libc::c_void,
        udata: *mut libc::c_void,
    ) -> HookResult<()> {
        let chain = unsafe { &mut *self.inner };
        hook_chain_reload(chain, node, before, after, udata)
    }

    /// Return `true` if the chain has no active callbacks.
    pub fn is_empty(&self) -> bool {
        let chain = unsafe { &*self.inner };
        hook_chain_is_empty(chain)
    }

    /// Return the number of active (READY) callbacks.
    pub fn len(&self) -> usize {
        let chain = unsafe { &*self.inner };
        chain
            .states
            .iter()
            .filter(|&&s| s == CHAIN_ITEM_STATE_READY)
            .count()
    }

    /// Access the underlying raw [`HookChain`] pointer.
    ///
    /// # Safety
    ///
    /// The pointer remains valid as long as this `Chain` is alive (or the
    /// owning chain in the global registry is alive, for non-owned chains).
    pub unsafe fn as_raw(&self) -> *mut HookChain {
        self.inner
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        let chain = unsafe { &mut *self.inner };
        if !hook_chain_is_empty(chain) {
            // Still has callbacks — just keep it installed
            return;
        }
        let origin = chain.hook.origin_addr as usize;
        let _ = inline::hook_uninstall(&chain.hook);
        alloc::hook_mem_unregister(origin);
        let chain_size = std::mem::size_of::<HookChain>();
        alloc::hook_mem_free(self.inner as *mut u8, chain_size);
    }
}

// SAFETY: Chain owns an allocation in executable memory. The raw pointer
// itself is Send + Sync because all mutation goes through &mut Chain or
// atomic state transitions (BUSY ↔ READY).
unsafe impl Send for Chain {}
unsafe impl Sync for Chain {}

// ---------------------------------------------------------------------------
// Public free-function API: hook_wrap / hook_unwrap
// ---------------------------------------------------------------------------

/// Wrap a function with before / after callbacks (chain-based inline hook).
///
/// Multiple wraps on the same function share a single chain allocation.
/// `argno` is the count of register arguments (0–12).
///
/// Unlike [`Chain::wrap`], this does **not** return a handle — use
/// [`hook_unwrap`] to tear down callbacks later.
///
/// # Safety
///
/// - `func` must point to valid, executable code.
/// - `before` and `after` may be null. When non-null, their signatures must
///   match the callback type corresponding to `argno` (see `HookChain*Callback`).
/// - The target function body must be ≥ 16 bytes.
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

    // If a chain already exists, just add to it
    if let Some(ptr) = alloc::hook_mem_lookup(origin) {
        let mut chain = unsafe { Chain::from_raw(ptr as *mut HookChain) };
        chain.add(before, after, udata)?;
        return Ok(());
    }

    // Create a new chain (via Chain::wrap, then leak the ownership so the
    // registry is the sole owner — hook_unwrap will clean up).
    let (chain_obj, _node) = unsafe { Chain::wrap(func, argno, before, after, udata)? };
    // Don't drop — the global registry now owns the allocation.
    // Take the raw pointer and forget the Chain wrapper.
    let _raw = chain_obj.inner;
    std::mem::forget(chain_obj);

    Ok(())
}

/// Unwrap callbacks by function-pointer match (legacy API).
///
/// Prefer [`hook_chain_remove`] with a [`ChainNodeId`] token when possible.
///
/// # Safety
///
/// `func` must be the same pointer passed to [`hook_wrap`].
/// `before` / `after` must match previously registered callbacks.
pub unsafe fn hook_unwrap(
    func: *const libc::c_void,
    before: *mut libc::c_void,
    after: *mut libc::c_void,
) {
    unsafe { hook_unwrap_remove(func, before, after, true) }
}

/// Remove callbacks by function-pointer match. If `remove` is `true` and
/// the chain becomes empty, the chain is uninstalled and freed.
///
/// Prefer [`hook_chain_remove`] with a [`ChainNodeId`] token when possible.
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

    // Legacy pointer-based removal — scan for matching before/after
    for i in 0..HOOK_CHAIN_NUM {
        if chain.states[i] == CHAIN_ITEM_STATE_READY
            && ((!before.is_null() && chain.befores[i] == before)
                || (!after.is_null() && chain.afters[i] == after))
        {
            hook_chain_remove(
                chain,
                ChainNodeId {
                    index: i as u8,
                    generation: chain.slot_generations[i],
                },
            );
            break;
        }
    }

    if !remove || !hook_chain_is_empty(chain) {
        return;
    }

    let _ = inline::hook_uninstall(&chain.hook);
    alloc::hook_mem_unregister(origin);
    let chain_size = std::mem::size_of::<HookChain>();
    alloc::hook_mem_free(ptr, chain_size);
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
