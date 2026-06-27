//! # Yuyu — Function-Pointer Hook Example
//!
//! Demonstrates `fp_hook()` / `fp_unhook()` and `fp_hook_wrap()` / `fp_hook_unwrap()`.
//!
//! ```sh
//! cargo run --example fp
//! ```

use std::ffi::c_void;
use yuyu::hook::{HookFargs2, fp_hook, fp_hook_unwrap, fp_hook_wrap2, fp_unhook};

// ---------------------------------------------------------------------------
// Functions pointed to by FP_VAR
// ---------------------------------------------------------------------------

extern "C" fn add(a: u64, b: u64) -> u64 {
    a + b
}
extern "C" fn sub(a: u64, b: u64) -> u64 {
    a - b
}

static mut FP_VAR: extern "C" fn(u64, u64) -> u64 = add;

// ---------------------------------------------------------------------------
// Callbacks for chain
// ---------------------------------------------------------------------------

unsafe extern "C" fn before_double(fargs: *mut HookFargs2, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    println!(
        "  [before]  arg0 was {}, doubling to {}",
        f.arg0,
        f.arg0 * 2
    );
    f.arg0 *= 2;
}

unsafe extern "C" fn after_times_10(fargs: *mut HookFargs2, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.ret;
    f.ret *= 10;
    println!("  [after]   ret was {}, ×10 → {}", old, f.ret);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Yuyu Function-Pointer Hook Example ===\n");

    let fp_addr = std::ptr::addr_of!(FP_VAR) as usize;

    // ---- 1. Original ----
    println!("1. Original: FP_VAR points to `add`.");
    unsafe {
        assert_eq!(FP_VAR(3, 4), 7);
    }
    println!("   FP_VAR(3, 4) = {}  (3+4 = 7)\n", unsafe { FP_VAR(3, 4) });

    // ---- 2. Simple fp_hook ----
    println!("2. Simple fp_hook (redirect to `sub`):");
    unsafe {
        let mut backup: *const c_void = std::ptr::null();
        fp_hook(fp_addr, sub as *const c_void, &mut backup).expect("fp_hook failed");

        let r = FP_VAR(10, 3);
        println!("   FP_VAR(10, 3) = {}  (10-3 = 7)", r);
        assert_eq!(r, 7);

        // Original via backup
        let orig: extern "C" fn(u64, u64) -> u64 = std::mem::transmute(backup);
        assert_eq!(orig(10, 3), 13);

        fp_unhook(fp_addr, backup);
    }
    unsafe {
        assert_eq!(FP_VAR(3, 4), 7);
    }
    println!("   after fp_unhook: ok\n");

    // ---- 3. fp_hook_wrap (chain) ----
    println!("3. fp_hook_wrap (chain with before/after):");
    unsafe {
        fp_hook_wrap2(fp_addr, before_double, after_times_10, std::ptr::null_mut())
            .expect("fp_hook_wrap failed");

        // FP_VAR(3, 4): add(3, 4)
        //   before: arg0 = 3*2 = 6
        //   original: 6+4 = 10
        //   after: 10 * 10 = 100
        let r = FP_VAR(3, 4);
        println!("   FP_VAR(3, 4) = {}  (expected: (3×2)+4 → 10×10 = 100)", r);
        assert_eq!(r, 100);

        fp_hook_unwrap(
            fp_addr,
            before_double as *mut c_void,
            after_times_10 as *mut c_void,
        );
    }
    unsafe {
        assert_eq!(FP_VAR(3, 4), 7);
    }
    println!("   after fp_hook_unwrap: ok\n");

    println!("=== All assertions passed! ===");
}
