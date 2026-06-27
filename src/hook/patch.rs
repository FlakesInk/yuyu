//! Branch resolution utilities.
//!
//! Many functions in ARM64 binaries start with a B / BTI instruction
//! (e.g., due to Procedure Linkage Table entries or Branch Target
//! Identification). This module recursively resolves such prefixes to
//! find the real first instruction of a function.

use crate::instruction::bit::{bits32, sign_extend};
use crate::instruction::decoder::{ARM64_BTI_C, ARM64_BTI_J, ARM64_BTI_JC, INST_B, MASK_B};

/// Resolve one level of branch indirection.
///
/// Reads the instruction at `addr`:
/// - If it's an unconditional branch (`B <offset>`), follows it.
/// - If it's a BTI hint (C / J / JC), skips to the next instruction.
/// - Otherwise returns `addr` unchanged.
///
/// # Safety
///
/// `addr` must point to readable, executable memory. Dereferences a raw pointer.
pub unsafe fn resolve_branch_once(addr: usize) -> usize {
    let inst = unsafe { *(addr as *const u32) };
    if inst & MASK_B == INST_B {
        let imm26 = bits32(inst, 25, 0).unwrap();
        let imm64 = sign_extend((imm26 as u64) << 2, 28) as usize;
        addr.wrapping_add(imm64)
    } else if inst == ARM64_BTI_C || inst == ARM64_BTI_J || inst == ARM64_BTI_JC {
        addr + 4
    } else {
        addr
    }
}

/// Resolve all branch/BTI prefixes to find the real function entry.
///
/// Follows a chain of `B` and `BTI` instructions until the address
/// stabilizes. This is the real address where code patching should occur.
pub fn resolve_branch(mut addr: usize) -> usize {
    loop {
        let ret = unsafe { resolve_branch_once(addr) };
        if addr == ret {
            break ret;
        }
        addr = ret;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::alloc;

    /// Build a small code buffer in executable memory for testing.
    fn make_code_buf(insts: &[u32]) -> *mut u8 {
        let size = insts.len() * 4;
        let ptr = alloc::hook_mem_alloc(size).expect("alloc failed");
        unsafe {
            let dst = ptr as *mut u32;
            for (i, &inst) in insts.iter().enumerate() {
                *dst.add(i) = inst;
            }
        }
        ptr
    }

    #[test]
    fn resolve_passthrough() {
        // Function with no prefix → resolve_branch returns same address
        let buf = make_code_buf(&[0xD65F03C0]); // RET
        let resolved = resolve_branch(buf as usize);
        assert_eq!(resolved, buf as usize);
        alloc::hook_mem_free(buf, 4);
    }

    #[test]
    fn resolve_single_b() {
        // B +8 → next instruction
        // imm26 = 2 (8/4)
        let buf = make_code_buf(&[0x14000002, 0xD65F03C0, 0xD503201F]);
        let resolved = resolve_branch(buf as usize);
        // Should resolve to buf+8 (past the B)
        assert_eq!(resolved, buf as usize + 8);
        alloc::hook_mem_free(buf, 12);
    }

    #[test]
    fn resolve_bti_c() {
        let buf = make_code_buf(&[ARM64_BTI_C, 0xD65F03C0]);
        let resolved = resolve_branch(buf as usize);
        assert_eq!(resolved, buf as usize + 4);
        alloc::hook_mem_free(buf, 8);
    }

    #[test]
    fn resolve_bti_j() {
        let buf = make_code_buf(&[ARM64_BTI_J, 0xD65F03C0]);
        let resolved = resolve_branch(buf as usize);
        assert_eq!(resolved, buf as usize + 4);
        alloc::hook_mem_free(buf, 8);
    }

    #[test]
    fn resolve_bti_then_b() {
        // BTI_J then B +4 → skip both
        let buf = make_code_buf(&[ARM64_BTI_J, 0x14000001, 0xD65F03C0, 0xD503201F]);
        let resolved = resolve_branch(buf as usize);
        assert_eq!(resolved, buf as usize + 8);
        alloc::hook_mem_free(buf, 16);
    }

    #[test]
    fn resolve_no_branch_returns_self() {
        let func = resolve_no_branch_returns_self as *const () as usize;
        let resolved = resolve_branch(func);
        assert_eq!(resolved, func);
    }
}
