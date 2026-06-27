//! # Yuyu — Relocation Example
//!
//! Demonstrates a hook on a function containing a **conditional branch**,
//! which triggers the instruction relocation code path. The branch target
//! must be recomputed when the instruction is moved to the backup buffer.
//!
//! ```sh
//! cargo run --example relocate
//! ```

use std::ffi::c_void;
use yuyu::hook::{hook, unhook};

// ---------------------------------------------------------------------------
// Target: a function with a conditional branch (CBZ)
// ---------------------------------------------------------------------------

/// Count leading zeros via a simple loop with a conditional branch.
/// The compiler will emit a CBZ or CBNZ instruction inside the loop,
/// which is a PC-relative branch that must be relocated.
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn count_trailing_ones(mut x: u64) -> u64 {
    let mut n = 0u64;
    while x & 1 != 0 {
        n += 1;
        x >>= 1;
    }
    // Force the compiler to emit plenty of instructions so the function
    // body is ≥ 16 bytes and the trampoline doesn't overflow.
    let _a = x.wrapping_mul(n);
    let _b = _a.wrapping_add(1);
    std::hint::black_box(&_b);
    n
}

// ---------------------------------------------------------------------------
// Replacement: count trailing zeros instead
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn count_trailing_zeros(mut x: u64) -> u64 {
    let mut n = 0u64;
    while x != 0 && x & 1 == 0 {
        n += 1;
        x >>= 1;
    }
    let _a = x.wrapping_mul(n);
    let _b = _a.wrapping_add(1);
    std::hint::black_box(&_b);
    n
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Yuyu Relocation Example ===\n");

    // Original: count trailing ones
    let r = count_trailing_ones(0b1011); // ones at bits 0 and 1 → 2
    println!(
        "1. Original: count_trailing_ones(0b1011) = {}  (expected 2)",
        r
    );
    assert_eq!(r, 2);

    // Hook: redirect to count_trailing_zeros
    println!("\n2. Hook: redirect to count_trailing_zeros");
    unsafe {
        let mut backup: *const c_void = std::ptr::null();
        hook(
            count_trailing_ones as *const c_void,
            count_trailing_zeros as *const c_void,
            &mut backup,
        )
        .expect("hook failed");

        // Now count_trailing_ones actually counts zeros
        let r = count_trailing_ones(0b1011);
        println!(
            "   count_trailing_ones(0b1011) = {}  (expected: trailing zeros = 0)",
            r
        );
        assert_eq!(r, 0); // 0b1011 has no trailing zeros

        let r = count_trailing_ones(0b1100);
        println!(
            "   count_trailing_ones(0b1100) = {}  (expected: trailing zeros = 2)",
            r
        );
        assert_eq!(r, 2); // 0b1100 has 2 trailing zeros

        // Call original via backup (relocated code)
        let orig: extern "C" fn(u64) -> u64 = std::mem::transmute(backup);
        let r = orig(0b1011);
        println!("   backup(0b1011) = {}  (expected: 2)", r);
        assert_eq!(r, 2); // original via relocated buffer

        unhook(count_trailing_ones as *const c_void);
    }

    // Restored
    let r = count_trailing_ones(0b1011);
    println!(
        "\n3. After unhook: count_trailing_ones(0b1011) = {}  (expected 2)",
        r
    );
    assert_eq!(r, 2);

    println!("\n=== All assertions passed! ===");
}
