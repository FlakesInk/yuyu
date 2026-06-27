# Yuyu

A lightweight ARM64 (AArch64) hooking library for Linux.

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

## Platform

- **Architecture**: AArch64 (ARM64) only
- **OS**: Linux
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
cargo run --example inline   # inline hook demo
cargo run --example fp       # function-pointer hook demo
```

## Run the tests

```sh
cargo test
cargo clippy --all-targets
```

## License

GPL-2.0-or-later — ported from [KernelPatch](https://github.com/bmax121/KernelPatch).
