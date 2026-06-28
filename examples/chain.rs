//! # Yuyu — 3-layer Hook Chain Example
//!
//! Demonstrates the `Chain` object API with three stacked callback pairs,
//! hot-reload of a middle node, and removal by `ChainNodeId`.
//!
//! ```sh
//! cargo run --example chain
//! ```

use std::ffi::c_void;
use yuyu::hook::{Chain, ChainNodeId, HookFargs1};

// ---------------------------------------------------------------------------
// Target function
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn compute(x: u64) -> u64 {
    let r = x.wrapping_mul(2);
    std::hint::black_box(&r);
    r
}

// ---------------------------------------------------------------------------
// Layer 1: double the input, add 1 to the result
// ---------------------------------------------------------------------------

unsafe extern "C" fn before_double(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.arg0;
    f.arg0 = old.wrapping_mul(2);
    println!("  [layer1 before]  arg0: {} → {}", old, f.arg0);
}

unsafe extern "C" fn after_add1(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.ret;
    f.ret = old.wrapping_add(1);
    println!("  [layer1 after]   ret:  {} → {}", old, f.ret);
}

// ---------------------------------------------------------------------------
// Layer 2: add 10 to input, multiply result by 10
// ---------------------------------------------------------------------------

unsafe extern "C" fn before_add10(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.arg0;
    f.arg0 = old.wrapping_add(10);
    println!("  [layer2 before]  arg0: {} → {}", old, f.arg0);
}

unsafe extern "C" fn after_mul10(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.ret;
    f.ret = old.wrapping_mul(10);
    println!("  [layer2 after]   ret:  {} → {}", old, f.ret);
}

// ---------------------------------------------------------------------------
// Layer 3: subtract 5 from input, add 100 to result
// ---------------------------------------------------------------------------

unsafe extern "C" fn before_sub5(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.arg0;
    f.arg0 = old.wrapping_sub(5);
    println!("  [layer3 before]  arg0: {} → {}", old, f.arg0);
}

unsafe extern "C" fn after_add100(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.ret;
    f.ret = old.wrapping_add(100);
    println!("  [layer3 after]   ret:  {} → {}", old, f.ret);
}

// ---------------------------------------------------------------------------
// Replacement callbacks for hot-reload demo
// ---------------------------------------------------------------------------

unsafe extern "C" fn before_mul3(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.arg0;
    f.arg0 = old.wrapping_mul(3);
    println!(
        "  [layer2* before] arg0: {} → {}  (hot-reloaded!)",
        old, f.arg0
    );
}

unsafe extern "C" fn after_mul100(fargs: *mut HookFargs1, _udata: *mut c_void) {
    let f = unsafe { &mut *fargs };
    let old = f.ret;
    f.ret = old.wrapping_mul(100);
    println!(
        "  [layer2* after]  ret:  {} → {}  (hot-reloaded!)",
        old, f.ret
    );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Yuyu 3-Layer Hook Chain Example ===\n");

    // Baseline
    let original = compute(3);
    println!("Baseline: compute(3) = {}  (3 × 2)\n", original);
    assert_eq!(original, 6);

    // ---- Build a 3-layer chain ----
    println!("--- Building 3-layer chain ---\n");
    unsafe {
        // Layer 1 (first) — this call allocates and installs the chain
        let (mut chain, node1) = Chain::wrap(
            compute as *const c_void,
            1, // argno = 1 (single u64 argument)
            before_double as *mut c_void,
            after_add1 as *mut c_void,
            std::ptr::null_mut(),
        )
        .expect("layer1 wrap failed");
        println!(
            "✓ layer1 added (node: index={}, gen={}), chain installed ({} active)\n",
            node1.index,
            node1.generation,
            chain.len()
        );

        // Layer 2 — add to the existing chain
        let node2: ChainNodeId = chain
            .add(
                before_add10 as *mut c_void,
                after_mul10 as *mut c_void,
                std::ptr::null_mut(),
            )
            .expect("layer2 add failed");
        println!(
            "✓ layer2 added (node: index={}, gen={}), {} active\n",
            node2.index,
            node2.generation,
            chain.len()
        );

        // Layer 3 — add to the existing chain
        let node3: ChainNodeId = chain
            .add(
                before_sub5 as *mut c_void,
                after_add100 as *mut c_void,
                std::ptr::null_mut(),
            )
            .expect("layer3 add failed");
        println!(
            "✓ layer3 added (node: index={}, gen={}), {} active\n",
            node3.index,
            node3.generation,
            chain.len()
        );

        // ---- Test the full 3-layer chain ----
        //
        // Before chain (forward):
        //   layer1: arg0 = 3×2 = 6
        //   layer2: arg0 = 6+10 = 16
        //   layer3: arg0 = 16-5 = 11
        // Original: compute(11) = 22
        // After chain (reverse):
        //   layer3: ret = 22+100 = 122
        //   layer2: ret = 122×10 = 1220
        //   layer1: ret = 1220+1 = 1221
        println!("--- Full 3-layer chain ---\n");
        let r = compute(3);
        println!("  → compute(3) = {}\n", r);
        assert_eq!(r, 1221);

        // ---- Hot-reload layer 2 ----
        println!("--- Hot-reloading layer 2 ---\n");
        println!("  Replacing: before_add10 / after_mul10");
        println!("       with: before_mul3  / after_mul100\n");

        chain
            .reload(
                node2,
                before_mul3 as *mut c_void,
                after_mul100 as *mut c_void,
                std::ptr::null_mut(),
            )
            .expect("hot-reload failed");
        println!("✓ layer2 hot-reloaded ({} active)\n", chain.len());

        // After reload:
        //   layer1 before: 3×2 = 6
        //   layer2 before: 6×3 = 18   (was +10, now ×3)
        //   layer3 before: 18-5 = 13
        // Original: compute(13) = 26
        //   layer3 after: 26+100 = 126
        //   layer2 after: 126×100 = 12600  (was ×10, now ×100)
        //   layer1 after: 12600+1 = 12601
        let r = compute(3);
        println!("  → compute(3) = {}\n", r);
        assert_eq!(r, 12601);

        // ---- Remove layer 3 by token ----
        println!("--- Removing layer 3 ---\n");
        chain.remove(node3);
        println!("✓ layer3 removed ({} active)\n", chain.len());

        // After removing layer3:
        //   layer1 before: 3×2 = 6
        //   layer2 before: 6×3 = 18
        // Original: compute(18) = 36
        //   layer2 after: 36×100 = 3600
        //   layer1 after: 3600+1 = 3601
        let r = compute(3);
        println!("  → compute(3) = {}\n", r);
        assert_eq!(r, 3601);

        // ---- Remove layer 2 by token ----
        println!("--- Removing layer 2 ---\n");
        chain.remove(node2);
        println!("✓ layer2 removed ({} active)\n", chain.len());

        // After removing layer2:
        //   layer1 before: 3×2 = 6
        // Original: compute(6) = 12
        //   layer1 after: 12+1 = 13
        let r = compute(3);
        println!("  → compute(3) = {}\n", r);
        assert_eq!(r, 13);

        // ---- Remove layer 1 and drop chain ----
        println!("--- Removing layer 1 and dropping chain ---\n");
        // The chain is still installed with layer1 active — remove it first.
        chain.remove(node1);
        println!("✓ layer1 removed, chain now empty — auto-uninstall on drop\n");
        // chain goes out of scope → drop → uninstall + free
    }

    // Chain is gone, original function is restored
    let r = compute(3);
    println!("After drop: compute(3) = {}  (original restored)\n", r);
    assert_eq!(r, 6);

    println!("=== All assertions passed! ===");
}
