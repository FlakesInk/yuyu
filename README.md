# Yuyu

A lightweight ARM64 (AArch64) hooking library for Linux / Android.

<https://git.colorsky.fun/Color/yuyu>

## Features

- **Inline hook** — overwrite function entry with a trampoline, relocate
  original instructions to a backup buffer
- **Function-pointer hook** — redirect indirect calls by overwriting a
  pointer variable
- **Hook chains** — register multiple before/after callback pairs on the
  same target (shared chain, auto-cleanup on unwrap)
- **0–12 arguments** — typed wrappers `hook_wrap0`…`hook_wrap12` and
  `fp_hook_wrap0`…`fp_hook_wrap12`
- **Argument modification** — callbacks can read/write arguments and the
  return value, or skip the original function entirely
- **Signature scanning** — AOB (Array of Bytes) pattern search across
  readable memory regions, with full-byte (`??`) and nibble (`?X`/`?X`)
  wildcards

## Platform

- **Architecture**: AArch64 (ARM64) only
- **OS**: Linux / Android
- **Rust**: edition 2024 (stable 1.85+)

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
yuyu = { git = "https://git.colorsky.fun/Color/yuyu" }
```

### Inline hook

```rust
use std::ffi::c_void;
use yuyu::hook::{hook, unhook};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn add(a: i32, b: i32) -> i32 { a + b }

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn add_replacement(a: i32, b: i32) -> i32 { a * b }

unsafe {
    let mut backup: *const c_void = std::ptr::null();
    hook(add as *const c_void, add_replacement as *const c_void, &mut backup)
        .expect("hook failed");

    assert_eq!(add(2, 3), 6);  // redirected

    let orig: extern "C" fn(i32, i32) -> i32 = std::mem::transmute(backup);
    assert_eq!(orig(2, 3), 5); // original via backup

    unhook(add as *const c_void);
}
```

### Hook wrap with callbacks

```rust
use yuyu::hook::{hook_wrap2, hook_unwrap, HookFargs2};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn mul(a: u64, b: u64) -> u64 { a * b }

unsafe extern "C" fn before(f: *mut HookFargs2, _: *mut c_void) {
    unsafe { (*f).arg0 += 1; }  // increment first argument
}

unsafe {
    hook_wrap2(mul as *const c_void, before, None, std::ptr::null_mut())
        .expect("wrap failed");

    assert_eq!(mul(2, 3), 9);  // (2+1) * 3

    hook_unwrap(mul as *const c_void, before, std::ptr::null_mut());
}
```

### Function-pointer hook

```rust
use yuyu::hook::{fp_hook, fp_unhook};

extern "C" fn add(a: u64, b: u64) -> u64 { a + b }
extern "C" fn sub(a: u64, b: u64) -> u64 { a - b }
static mut FP: extern "C" fn(u64, u64) -> u64 = add;

unsafe {
    let addr = std::ptr::addr_of!(FP) as usize;
    let mut backup: *const c_void = std::ptr::null();
    fp_hook(addr, sub as *const c_void, &mut backup).unwrap();

    assert_eq!(FP(10, 3), 7);  // sub: 10-3

    fp_unhook(addr, backup);
    assert_eq!(FP(3, 4), 7);   // add: 3+4
}
```

### Signature scanning

| Function | Scope |
|----------|-------|
| `sig_scan` | All readable regions in `/proc/self/maps` |
| `sig_scan_module` | Readable regions with pathname containing a given string |
| `sig_scan_range` | A caller-specified `[addr, addr+size)` interval (unsafe) |
| `sig_scan_all` | Same as `sig_scan`, but returns every match |

```rust
use std::str::FromStr;
use yuyu::memory::sigscan::{Signature, sig_scan, sig_scan_module, sig_scan_range};

// Scan all readable memory
let sig = Signature::from_str("FD 7B BF A9 FD 03 00 91").unwrap();
if let Some(addr) = sig_scan(&sig) {
    println!("Found at 0x{:X}", addr);
}

// Restrict to a module (case-insensitive substring match on pathname)
let sig = Signature::from_str("FD 7B ?? A9 ?? 03 00 91").unwrap();
if let Some(addr) = sig_scan_module(&sig, "libc.so") {
    println!("Found in libc at 0x{:X}", addr);
}

// Restrict to a caller-specified address range
unsafe {
    if let Some(addr) = sig_scan_range(&sig, 0x7f000000, 0x1000) {
        println!("Found at 0x{:X}", addr);
    }
}
```

## Requirements for target functions

Inline hooks overwrite the first 4 instructions (16 bytes). The target
function **must** be ≥ 16 bytes:

```rust
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn my_func(x: u64) -> u64 {
    let r = x + 1;
    std::hint::black_box(&r);  // prevents single-instruction body
    r
}
```

Function-pointer hooks have no size requirement.

## Run the examples

```sh
cargo run --example inline    # inline hook demo
cargo run --example fp        # function-pointer hook demo
cargo run --example relocate  # relocation with conditional branch
cargo run --example sigscan   # signature scanning demo
```

## Run the tests

```sh
cargo test
cargo clippy --all-targets
```

## License

GPL-2.0-or-later — ported from [KernelPatch](https://github.com/bmax121/KernelPatch).
