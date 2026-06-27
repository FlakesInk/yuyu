//! # Yuyu — Inline Hook Example
//!
//! Demonstrates `hook()` / `unhook()` (simple) and `hook_wrap()` / `hook_unwrap()` (chain).
//!
//! ```sh
//! cargo run --example inline
//! ```

use std::ffi::c_void;
use yuyu::hook::{HookFargs3, hook, hook_unwrap, hook_wrap3, unhook};

// ---------------------------------------------------------------------------
// Target and replacement
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn mul_add(a: u64, b: u64, c: u64) -> u64 {
    let r = a.wrapping_mul(b).wrapping_add(c);
    std::hint::black_box(&r);
    r
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn mul_add_replacement(a: u64, b: u64, c: u64) -> u64 {
    let r = a.wrapping_add(b).wrapping_add(c);
    std::hint::black_box(&r);
    r
}

// ---------------------------------------------------------------------------
// Callbacks for chain
// ---------------------------------------------------------------------------

unsafe extern "C" fn before_double_a(fargs: *mut HookFargs3, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    println!(
        "  [before]  arg0 was {}, doubling to {}",
        f.arg0,
        f.arg0 * 2
    );
    f.arg0 *= 2;
}

unsafe extern "C" fn after_add_100(fargs: *mut HookFargs3, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.ret;
    f.ret += 100;
    println!("  [after]   ret was {}, adding 100 → {}", old, f.ret);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Yuyu Inline Hook Example ===\n");

    // ---- 1. Simple hook ----
    println!("1. Simple hook (hook / unhook):");
    unsafe {
        let mut backup: *const c_void = std::ptr::null();
        hook(
            mul_add as *const c_void,
            mul_add_replacement as *const c_void,
            &mut backup,
        )
        .expect("hook failed");

        // Hooked: mul_add → mul_add_replacement
        let r = mul_add(2, 3, 4);
        println!("   mul_add(2, 3, 4) = {}  (expected: 2+3+4 = 9)", r);
        assert_eq!(r, 9);

        // Call original via backup pointer
        let orig: extern "C" fn(u64, u64, u64) -> u64 = std::mem::transmute(backup);
        assert_eq!(orig(2, 3, 4), 10);

        unhook(mul_add as *const c_void);
    }
    // Restored
    assert_eq!(mul_add(2, 3, 4), 10);
    println!("   after unhook: ok\n");

    // ---- 2. Hook wrap (chain) ----
    println!("2. Hook wrap (chain with before/after):");
    unsafe {
        hook_wrap3(
            mul_add as *const c_void,
            before_double_a,
            after_add_100,
            std::ptr::null_mut(),
        )
        .expect("wrap failed");

        // mul_add(2,3,4): before doubles arg0 → 4*3+4 = 16; after adds 100 → 116
        let r = mul_add(2, 3, 4);
        println!(
            "   mul_add(2, 3, 4) = {}  (expected: (2×2)×3+4 + 100 = 116)",
            r
        );
        assert_eq!(r, 116);

        hook_unwrap(
            mul_add as *const c_void,
            before_double_a as *mut c_void,
            after_add_100 as *mut c_void,
        );
    }
    assert_eq!(mul_add(2, 3, 4), 10);
    println!("   after unwrap: ok\n");

    println!("=== All assertions passed! ===");
}
