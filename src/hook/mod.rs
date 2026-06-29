//! Inline hook module for ARM64 (AArch64).
//!
//! # Overview
//!
//! Three public APIs are provided:
//!
//! | API | Signature | Multiple hooks? | Use case |
//! |-----|-----------|----------------|----------|
//! | [`hook`] / [`unhook`] | Simple replace | ❌ one-shot only | Quick single-target inline hook |
//! | [`hook_wrap`] / [`hook_unwrap`] | Chain with before/after callbacks | ✅ | Managed multi-callback inline hook |
//! | [`fp_hook`] / [`fp_unhook`] / [`fp_hook_wrap`] / [`fp_hook_unwrap`] | Pointer overwrite | ✅ (fp_hook_wrap) | Redirect indirect calls via function pointers |
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ hook / hook_wrap (public API)                            │
//! ├──────────────────────────────────────────────────────────┤
//! │ inline.rs: hook_prepare, hook_install, hook_uninstall    │
//! │   ├── instruction::reloc::relocate_inst                  │
//! │   ├── instruction::writer::branch_from_to / relo_*       │
//! │   └── memory::protect::hotpatch                         │
//! ├──────────────────────────────────────────────────────────┤
//! │ chain.rs: hook_wrap, hook_unwrap, chain add/remove       │
//! │   ├── inline.rs (hook_prepare, hook_install, etc.)       │
//! │   ├── trampoline.rs (transit header generation)          │
//! │   └── memory::alloc (mmap + registry)                    │
//! ├──────────────────────────────────────────────────────────┤
//! │ trampoline.rs: transit dispatch functions                │
//! │   ├── context.rs: Hook, HookChain, HookFargs*            │
//! │   └── memory::alloc: mmap allocation + global registry   │
//! ├──────────────────────────────────────────────────────────┤
//! │ fp.rs: function-pointer hook + fp chain                  │
//! │   ├── context.rs: FpHook, FpHookChain, HookFargs*        │
//! │   └── memory::alloc: mmap allocation + global registry   │
//! ├──────────────────────────────────────────────────────────┤
//! │ patch.rs: resolve_branch (follow B / BTI prefixes)       │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Module list
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`context`] | `Hook`, `HookChain`, `HookFargs`, `FpHook`, `FpHookChain`, callback types |
//! | [`patch`] | `resolve_branch` — follow B/BTI prefixes to real code |
//! | [`inline`] | `hook_prepare` / `hook_install` / `hook_uninstall` + `hook()` / `unhook()` |
//! | [`trampoline`] | Low-level transit dispatch functions (`_yuyu_transit*`) |
//! | [`chain`] | `hook_wrap` / `hook_unwrap`, `Chain` object, `ChainNodeId`, chain add/remove/reload |
//! | [`fp`] | `fp_hook` / `fp_unhook` / `fp_hook_wrap` / `fp_hook_unwrap` — function-pointer hook |
//!
//! # Safety
//!
//! All hook operations are inherently **unsafe**. The caller must ensure:
//! - Function pointers are valid and point to executable code
//! - Callback signatures match the original function's ABI exactly
//! - Hooks are uninstalled before the target function or library is unloaded
//! - No concurrent modification of hook chains

pub mod context;
pub mod patch;

pub mod fp;

pub mod inline;

pub mod chain;

pub mod trampoline;

// Re-export key types and functions for convenience
pub use context::{
    CHAIN_ITEM_STATE_BUSY, CHAIN_ITEM_STATE_EMPTY, CHAIN_ITEM_STATE_READY, ChainNodeId, FpHook,
    FpHookChain, HOOK_CHAIN_NUM, Hook, HookChain, HookChain0Callback, HookChain1Callback,
    HookChain2Callback, HookChain3Callback, HookChain4Callback, HookChain5Callback,
    HookChain6Callback, HookChain7Callback, HookChain8Callback, HookChain9Callback,
    HookChain10Callback, HookChain11Callback, HookChain12Callback, HookFargs0, HookFargs1,
    HookFargs2, HookFargs3, HookFargs4, HookFargs5, HookFargs6, HookFargs7, HookFargs8, HookFargs9,
    HookFargs10, HookFargs11, HookFargs12, HookLocal, fp_get_origin_func, wrap_get_origin_func,
};

pub use inline::{hook, hook_install, hook_prepare, hook_uninstall, unhook};

pub use chain::{
    Chain, hook_chain_add, hook_chain_install, hook_chain_reload, hook_chain_remove,
    hook_chain_uninstall, hook_unwrap, hook_unwrap_remove, hook_wrap, hook_wrap0, hook_wrap1,
    hook_wrap2, hook_wrap3, hook_wrap4, hook_wrap5, hook_wrap6, hook_wrap7, hook_wrap8, hook_wrap9,
    hook_wrap10, hook_wrap11, hook_wrap12,
};

pub use fp::{
    fp_hook, fp_hook_unwrap, fp_hook_wrap, fp_hook_wrap0, fp_hook_wrap1, fp_hook_wrap2,
    fp_hook_wrap3, fp_hook_wrap4, fp_hook_wrap5, fp_hook_wrap6, fp_hook_wrap7, fp_hook_wrap8,
    fp_hook_wrap9, fp_hook_wrap10, fp_hook_wrap11, fp_hook_wrap12, fp_unhook,
};
