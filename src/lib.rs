//! # Yuyu — ARM64 Inline Hook Library
//!
//! A lightweight, low-level hooking library for **AArch64 Linux**, ported
//! from the [KernelPatch](https://github.com/bmax121/KernelPatch) kernel
//! module. Supports three hooking strategies:
//!
//! | Strategy | Targets | Example |
//! |----------|---------|---------|
//! | **Inline hook** | Function code (patching instructions) | `hook()`, `hook_wrap()` |
//! | **Function-pointer hook** | Pointer variables (overwriting pointers) | `fp_hook()`, `fp_hook_wrap()` |
//!
//! ## How inline hooks work
//!
//! ```text
//! Before hook:                    After hook:
//!
//!   func:                           func:
//!     inst0  --.                      trampoline --> replace()
//!     inst1    | original flow          (NOPs)
//!     inst2    |                      backup (relo_buf):
//!     ...      |                        relo(inst0)
//!     ret      <-- callers             relo(inst1)
//!                                       jump back --> func+N
//! ```
//!
//! 1. **Backup** — copy the first N instructions from the target function.
//! 2. **Trampoline** — overwrite those N instructions with a jump to the
//!    replacement (or transit dispatcher for chains).
//! 3. **Relocate** — transform each overwritten instruction into a
//!    position-independent sequence that runs from a different address.
//!    The relocated buffer is what `backup` points to.
//! 4. **Jump back** — append a branch at the end of the relocated buffer
//!    that returns to `func + N`, so the original function body still
//!    executes after the relocated prefix.
//!
//! Function-pointer hooks are simpler: they just overwrite a pointer
//! variable with the replacement address, saving the original value.
//!
//! ## API overview
//!
//! | API | Target | Multiple hooks? | Use case |
//! |-----|--------|----------------|----------|
//! | [`hook::hook()`] / [`hook::unhook()`] | Function code | ❌ one-shot | Quick single-target inline hook |
//! | [`hook::hook_wrap()`] / [`hook::hook_unwrap()`] | Function code | ✅ chain | Managed multi-callback inline hook |
//! | [`hook::fp_hook()`] / [`hook::fp_unhook()`] | Pointer variable | ❌ one-shot | Redirect indirect calls |
//! | [`hook::fp_hook_wrap()`] / [`hook::fp_hook_unwrap()`] | Pointer variable | ✅ chain | Managed multi-callback fp hook |
//!
//! ## Requirements for target functions
//!
//! Inline hooks overwrite the first 4 instructions (16 bytes) of the target
//! function with a trampoline. The target function **must** be at least
//! 16 bytes large, otherwise the trampoline spills into adjacent code and
//! causes undefined behaviour.
//!
//! To guarantee this, annotate target functions with both
//! `#[unsafe(no_mangle)]` and `#[inline(never)]`:
//!
//! ```rust
//! #[unsafe(no_mangle)]
//! #[inline(never)]
//! extern "C" fn my_func(x: u64) -> u64 {
//!     // Avoid single-instruction bodies like `x + 1`.
//!     // Use black_box or multiple statements to reach ≥ 16 bytes.
//!     let r = x + 1;
//!     std::hint::black_box(&r);
//!     r
//! }
//! ```
//!
//! | Attribute | Reason |
//! |-----------|--------|
//! | `#[unsafe(no_mangle)]` | Stable symbol name so the hook can locate the function |
//! | `#[inline(never)]` | Prevents the compiler from inlining the call and bypassing the hook |
//! | Body ≥ 16 bytes | Trampoline is 4 instructions; smaller bodies overflow into adjacent code |
//! | `extern "C"` | Ensures predictable AArch64 calling convention |
//!
//! Function-pointer hooks have no size requirement — they only overwrite a
//! pointer variable.
//!
//! ## Quick example — inline `hook` / `unhook`
//!
//! ```rust,no_run
//! use yuyu::hook::{hook, unhook};
//! use std::ffi::c_void;
//!
//! extern "C" fn add(a: i32, b: i32) -> i32 { a + b }
//! extern "C" fn add_replacement(a: i32, b: i32) -> i32 { a * b }
//!
//! unsafe {
//!     let mut backup: *const c_void = std::ptr::null();
//!     hook(
//!         add as *const c_void,
//!         add_replacement as *const c_void,
//!         &mut backup,
//!     ).expect("hook failed");
//!
//!     assert_eq!(add(2, 3), 6);   // redirected to replacement
//!
//!     let orig: extern "C" fn(i32, i32) -> i32 = std::mem::transmute(backup);
//!     assert_eq!(orig(2, 3), 5);  // original via backup
//!
//!     unhook(add as *const c_void);
//! }
//! ```
//!
//! ## Quick example — `hook_wrap` (chain)
//!
//! ```rust,no_run
//! use yuyu::hook::{hook_wrap2, hook_unwrap, HookFargs2};
//! use std::ffi::c_void;
//!
//! extern "C" fn greet(name: *const u8, len: u64) -> u64 { len }
//!
//! unsafe extern "C" fn before(fargs: *mut HookFargs2, _udata: *mut c_void) {
//!     unsafe { (*fargs).arg1 += 1; } // bump len
//! }
//! unsafe extern "C" fn after(fargs: *mut HookFargs2, _udata: *mut c_void) {
//!     unsafe { (*fargs).ret *= 2; }
//! }
//!
//! unsafe {
//!     hook_wrap2(
//!         greet as *const c_void, before, after, std::ptr::null_mut(),
//!     ).expect("wrap failed");
//!
//!     assert_eq!(greet(std::ptr::null(), 5), 12); // 2 × (5 + 1)
//!
//!     hook_unwrap(greet as *const c_void,
//!         before as *mut c_void, after as *mut c_void);
//! }
//! ```
//!
//! ## Quick example — `Chain` object (hot-reloadable)
//!
//! ```rust,no_run
//! use yuyu::hook::{Chain, ChainNodeId, HookFargs2};
//! use std::ffi::c_void;
//!
//! extern "C" fn add(a: u64, b: u64) -> u64 { a + b }
//!
//! unsafe extern "C" fn before(fargs: *mut HookFargs2, _udata: *mut c_void) {
//!     unsafe { (*fargs).arg0 += 1; }
//! }
//! unsafe extern "C" fn after(fargs: *mut HookFargs2, _udata: *mut c_void) {
//!     unsafe { (*fargs).ret *= 2; }
//! }
//!
//! unsafe {
//!     let (mut chain, _node1) = Chain::wrap(
//!         add as *const c_void, 2,
//!         before as *mut c_void,
//!         after as *mut c_void,
//!         std::ptr::null_mut(),
//!     ).expect("wrap failed");
//!
//!     assert_eq!(add(2, 3), 12); // 2 × (3 + 3)
//!
//!     // Add another callback pair — get a token back
//!     let node: ChainNodeId = chain.add(
//!         before as *mut c_void,
//!         after as *mut c_void,
//!         std::ptr::null_mut(),
//!     ).expect("add failed");
//!
//!     // Hot-reload the second node
//!     chain.reload(node,
//!         std::ptr::null_mut(),   // no before
//!         after as *mut c_void,   // keep after
//!         std::ptr::null_mut(),
//!     ).expect("reload failed");
//!
//!     // Remove it by token
//!     chain.remove(node);
//!     assert_eq!(chain.len(), 1);
//!
//!     // Chain auto-uninstalls when dropped
//! }
//! ```
//!
//! ## Quick example — `fp_hook` / `fp_unhook`
//!
//! ```rust,no_run
//! use std::ffi::c_void;
//! use yuyu::hook::{fp_hook, fp_unhook};
//!
//! extern "C" fn add(a: u64, b: u64) -> u64 { a + b }
//! extern "C" fn sub(a: u64, b: u64) -> u64 { a - b }
//! static mut FP: extern "C" fn(u64, u64) -> u64 = add;
//!
//! unsafe {
//!     let fp_addr = std::ptr::addr_of!(FP) as usize;
//!
//!     // Redirect FP from `add` to `sub`
//!     let mut backup: *const c_void = std::ptr::null();
//!     fp_hook(fp_addr, sub as *const c_void, &mut backup).unwrap();
//!     assert_eq!(FP(10, 3), 7);   // sub: 10-3
//!
//!     // Restore original
//!     fp_unhook(fp_addr, backup);
//!     assert_eq!(FP(3, 4), 7);    // add: 3+4
//! }
//! ```
//!
//! ## Callback argument types
//!
//! Choose the right wrapper and types by argument count:
//!
//! | Args | Inline wrapper | FP wrapper | `HookFargs*` | Fields |
//! |------|---------------|------------|--------------|--------|
//! | 0 | `hook_wrap0` | `fp_hook_wrap0` | [`hook::HookFargs0`] | `ret`, `skip_origin`, `local` |
//! | 1 | `hook_wrap1` | `fp_hook_wrap1` | [`hook::HookFargs1`] | + `arg0` |
//! | 2 | `hook_wrap2` | `fp_hook_wrap2` | [`hook::HookFargs2`] | + `arg0`–`arg1` |
//! | 3 | `hook_wrap3` | `fp_hook_wrap3` | [`hook::HookFargs3`] | + `arg0`–`arg2` |
//! | 4 | `hook_wrap4` | `fp_hook_wrap4` | [`hook::HookFargs4`] | + `arg0`–`arg3` |
//! | 5 | `hook_wrap5` | `fp_hook_wrap5` | [`hook::HookFargs5`] | + `arg0`–`arg4` |
//! | 6 | `hook_wrap6` | `fp_hook_wrap6` | [`hook::HookFargs6`] | + `arg0`–`arg5` |
//! | 7 | `hook_wrap7` | `fp_hook_wrap7` | [`hook::HookFargs7`] | + `arg0`–`arg6` |
//! | 8 | `hook_wrap8` | `fp_hook_wrap8` | [`hook::HookFargs8`] | + `arg0`–`arg7` |
//! | 9–12 | `hook_wrap9`…`12` | `fp_hook_wrap9`…`12` | [`hook::HookFargs9`]… | + `arg0`–`arg11` |
//!
//! Each `HookFargs` struct also exposes:
//! - `chain` — pointer back to the chain struct
//! - `skip_origin` — set to non-zero to skip the original function
//! - `local` — 8 × `u64` scratch area for before ↔ after state
//! - `ret` — return value (write in `after` callback to override)
//!
//! Call [`hook::wrap_get_origin_func`] (inline) or
//! [`hook::fp_get_origin_func`] (fp) from within a callback to obtain a
//! function pointer to the original implementation.
//!
//! ## Platform support
//!
//! - **Architecture**: AArch64 (ARM64) only
//! - **OS**: Linux (`mprotect`, `mmap`, `/proc/self/maps`)
//! - **Rust edition**: 2024+
//!
//! ## Running the examples
//!
//! ```sh
//! cargo run --example inline   # inline hook demo
//! cargo run --example fp       # function-pointer hook demo
//! ```
//!
//! ## Safety
//!
//! All hook operations are **inherently unsafe**. The caller must ensure:
//! - Target functions have stable addresses (`#[unsafe(no_mangle)]`) and are
//!   large enough (≥ 16 bytes) to fit the trampoline without overflowing
//! - Target functions / pointers are in valid, mapped memory
//! - Hooks are uninstalled before the target or its library is unloaded
//! - Callback signatures **exactly** match the original function's ABI
//! - No concurrent modification of hook chains

#[cfg(target_arch = "aarch64")]
pub mod error;
pub mod hook;
pub mod instruction;
pub mod memory;
pub mod utils;
