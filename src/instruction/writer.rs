//! ARM64 machine-code generation.
//!
//! # Branch primitives
//!
//! | Function | Produces | Use case |
//! |----------|----------|----------|
//! | [`branch_relative`] | `B <offset>` | Short-range (±128 MiB) direct jump |
//! | [`branch_absolute`] | `LDR X17, #8; BR X17; .quad addr` | Any-range indirect jump |
//! | [`ret_absolute`] | `LDR X17, #8; RET X17; .quad addr` | Any-range indirect tail-call |
//! | [`branch_from_to`] | Delegates to `ret_absolute` | Hook trampolines (default) |
//!
//! # Relocation sequences
//!
//! When a hook overwrites original instructions, each overwritten instruction
//! needs a "relocated" version that can execute at a different address. The
//! `relo_*` functions generate these sequences:
//!
//! | Function | Handles | Output size |
//! |----------|---------|-------------|
//! | [`relo_b`] | B / BL / BC | 6–8 words |
//! | [`relo_adr`] | ADR / ADRP | 4 words |
//! | [`relo_ldr_int`] | LDR W/X/SW literal | 6 words |
//! | [`relo_ldr_simd`] | LDR S/D/Q + PRFM literal | 8 words |
//! | [`relo_cb`] | CBZ / CBNZ | 6 words |
//! | [`relo_tb`] | TBZ / TBNZ | 6 words |
//! | [`relo_ignore`] | Unrecognized | 2 words (passthrough) |

use crate::instruction::decoder::ARM64_NOP;

/// Maximum range for a relative B instruction: ±128 MiB.
const B_REL_RANGE: usize = (1 << 25) << 2;

/// Check whether a relative branch from `src` to `dst` fits in a B instruction.
#[inline]
pub fn can_b_rel(src: u64, dst: u64) -> bool {
    if dst >= src {
        (dst - src) <= B_REL_RANGE as u64
    } else {
        (src - dst) <= B_REL_RANGE as u64
    }
}

/// Generate a relative branch (`B <label>`) if within range.
/// Returns the instruction sequence (2 x u32: B + NOP) or None if out of range.
pub fn branch_relative(buf: &mut [u32], src: u64, dst: u64) -> Option<usize> {
    if can_b_rel(src, dst) {
        let diff = dst.wrapping_sub(src);
        buf[0] = 0x14000000u32 | (((diff & 0x0FFFFFFF) >> 2) as u32); // B <label>
        buf[1] = ARM64_NOP;
        Some(2)
    } else {
        None
    }
}

/// Generate an absolute indirect branch to `addr` via X17.
/// Sequence: LDR X17, #8 ; BR X17 ; .quad addr
/// Returns the number of u32 words written (4).
pub fn branch_absolute(buf: &mut [u32], addr: u64) -> usize {
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xD61F0220; // BR X17
    buf[2] = addr as u32;
    buf[3] = (addr >> 32) as u32;
    4
}

/// Generate an absolute return branch to `addr` via X17.
/// Sequence: LDR X17, #8 ; RET X17 ; .quad addr
/// Returns the number of u32 words written (4).
pub fn ret_absolute(buf: &mut [u32], addr: u64) -> usize {
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xD65F0220; // RET X17
    buf[2] = addr as u32;
    buf[3] = (addr >> 32) as u32;
    4
}

/// Generate a branch-from-to sequence. Always uses ret_absolute (4 words)
/// which is safe for any distance.
/// Returns the number of u32 words written.
pub fn branch_from_to(buf: &mut [u32], _src: u64, dst: u64) -> usize {
    ret_absolute(buf, dst)
}

// ---------------------------------------------------------------------------
// Relocation instruction builders
// ---------------------------------------------------------------------------

/// Relocate a B / BL / BC instruction.
/// Writes the replacement instruction sequence into `buf`.
/// Returns the number of u32 words written.
pub fn relo_b(buf: &mut [u32], inst: u32, target_addr: u64, is_bl: bool, is_bc: bool) -> usize {
    let mut idx = 0usize;
    if is_bc {
        // B.<cond> #8 (skip the NOP/LDR pair when condition is false)
        buf[idx] = (inst & 0xFF00001F) | 0x40;
        idx += 1;
        buf[idx] = 0x14000006; // B #24 (skip to the RET X17)
        idx += 1;
    }
    // LDR X17, #8
    buf[idx] = 0x58000051;
    idx += 1;
    // B #12
    buf[idx] = 0x14000003;
    idx += 1;
    // .quad target_addr
    buf[idx] = target_addr as u32;
    idx += 1;
    buf[idx] = (target_addr >> 32) as u32;
    idx += 1;

    if is_bl {
        // ADR X30, . (return address = current PC)
        buf[idx] = 0x1000001E;
        idx += 1;
        // ADD X30, X30, #12
        buf[idx] = 0x910033DE;
        idx += 1;
        // RET X17
        buf[idx] = 0xD65F0220;
        idx += 1;
    } else {
        // RET X17
        buf[idx] = 0xD65F0220;
        idx += 1;
    }
    buf[idx] = ARM64_NOP;
    idx + 1
}

/// Relocate an ADR / ADRP instruction.
/// Writes 4 u32 words into `buf`.
pub fn relo_adr(buf: &mut [u32], rd: u32, target_addr: u64) {
    // LDR Xd, #8
    buf[0] = 0x58000040u32 | rd;
    // B #12
    buf[1] = 0x14000003;
    // .quad target_addr
    buf[2] = target_addr as u32;
    buf[3] = (target_addr >> 32) as u32;
}

/// Relocate an LDR literal (integer: Wt/Xt/LDRSW).
/// Writes 6 u32 words into `buf`.
pub fn relo_ldr_int(buf: &mut [u32], rt: u32, target_addr: u64, is_64bit: bool, is_ldrsw: bool) {
    // LDR Xt, #12
    buf[0] = 0x58000060u32 | rt;
    if is_ldrsw {
        // LDRSW Xt, [Xt]
        buf[1] = 0xB9800000 | rt | (rt << 5);
    } else if is_64bit {
        // LDR Xt, [Xt]
        buf[1] = 0xF9400000 | rt | (rt << 5);
    } else {
        // LDR Wt, [Xt]
        buf[1] = 0xB9400000 | rt | (rt << 5);
    }
    // B #16
    buf[2] = 0x14000004;
    buf[3] = ARM64_NOP;
    // .quad target_addr
    buf[4] = target_addr as u32;
    buf[5] = (target_addr >> 32) as u32;
}

/// Relocate an LDR literal (SIMD/FP or PRFM).
/// Writes 8 u32 words into `buf`.
pub fn relo_ldr_simd(buf: &mut [u32], rt: u32, target_addr: u64, simd_type: u8) {
    // STP X16, X17, [SP, #-0x10]!
    buf[0] = 0xA93F47F0;
    // LDR X17, #16
    buf[1] = 0x58000091;

    match simd_type {
        0 => buf[2] = 0xF9800220 | rt,    // PRFM Rt, [X17]
        1 => buf[2] = 0xBD400220 | rt,    // LDR St, [X17]
        2 => buf[2] = 0xFD400220 | rt,    // LDR Dt, [X17]
        _ => buf[2] = 0x3DC00220u32 | rt, // LDR Qt, [X17]
    }

    // LDR X17, [SP, #-0x8]
    buf[3] = 0xF85F83F1;
    // B #16
    buf[4] = 0x14000004;
    buf[5] = ARM64_NOP;
    // .quad target_addr
    buf[6] = target_addr as u32;
    buf[7] = (target_addr >> 32) as u32;
}

/// Relocate a CBZ / CBNZ instruction.
/// Writes 6 u32 words into `buf`.
pub fn relo_cb(buf: &mut [u32], inst: u32, target_addr: u64) {
    // CB(N)Z Rt, #8
    buf[0] = (inst & 0xFF00001F) | 0x40;
    // B #20
    buf[1] = 0x14000005;
    // LDR X17, #8
    buf[2] = 0x58000051;
    // RET X17
    buf[3] = 0xD65F0220;
    // .quad target_addr
    buf[4] = target_addr as u32;
    buf[5] = (target_addr >> 32) as u32;
}

/// Relocate a TBZ / TBNZ instruction.
/// Writes 6 u32 words into `buf`.
pub fn relo_tb(buf: &mut [u32], inst: u32, target_addr: u64) {
    // TB(N)Z Rt, #<imm>, #8
    buf[0] = (inst & 0xFFF8001F) | 0x40;
    // B #20
    buf[1] = 0x14000005;
    // LDR X17, #8
    buf[2] = 0x58000051;
    // RET X17
    buf[3] = 0xD61F0220;
    // .quad target_addr
    buf[4] = target_addr as u32;
    buf[5] = (target_addr >> 32) as u32;
}

/// Pass-through for ignored/unsupported instructions.
/// Writes 2 u32 words (original inst + NOP).
pub fn relo_ignore(buf: &mut [u32], inst: u32) {
    buf[0] = inst;
    buf[1] = ARM64_NOP;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- can_b_rel ----

    #[test]
    fn can_b_rel_within_range() {
        // +128 MiB is the max range
        let max_range = (1u64 << 25) << 2;
        assert!(can_b_rel(0, max_range));
        assert!(can_b_rel(max_range, 0));
    }

    #[test]
    fn can_b_rel_out_of_range() {
        let max_range = (1u64 << 25) << 2;
        assert!(!can_b_rel(0, max_range + 4));
    }

    // ---- branch_relative ----

    #[test]
    fn branch_relative_within_range() {
        let mut buf = [0u32; 4];
        let n = branch_relative(&mut buf, 0x1000, 0x1008);
        assert_eq!(n, Some(2));
        // buf[0] should be B #8 (imm26=2)
        assert_eq!(buf[0], 0x14000002);
        assert_eq!(buf[1], ARM64_NOP);
    }

    #[test]
    fn branch_relative_out_of_range() {
        let mut buf = [0u32; 4];
        let n = branch_relative(&mut buf, 0, 0x1000_0000_0000);
        assert_eq!(n, None);
    }

    // ---- branch_absolute ----

    #[test]
    fn branch_absolute_encodes_address() {
        let mut buf = [0u32; 4];
        let addr = 0xABCD_1234_5678;
        let n = branch_absolute(&mut buf, addr);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x58000051); // LDR X17, #8
        assert_eq!(buf[1], 0xD61F0220); // BR X17
        // Low 32 bits of addr
        assert_eq!(buf[2], addr as u32);
        // High 32 bits
        assert_eq!(buf[3], (addr >> 32) as u32);
    }

    // ---- ret_absolute ----

    #[test]
    fn ret_absolute_encodes_address() {
        let mut buf = [0u32; 4];
        let addr = 0xDEAD_BEEF_CAFE;
        let n = ret_absolute(&mut buf, addr);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x58000051); // LDR X17, #8
        assert_eq!(buf[1], 0xD65F0220); // RET X17
        assert_eq!(buf[2], addr as u32);
        assert_eq!(buf[3], (addr >> 32) as u32);
    }

    // ---- relo_b (B / BL / BC) ----

    #[test]
    fn relo_b_simple() {
        let mut buf = [0u32; 16];
        // Relocate a B to target 0x4000
        let n = relo_b(&mut buf, 0x14000004, 0x4000, false, false);
        assert!(n > 0);
        // Should produce: LDR X17, #8 ; B #12 ; .quad 0x4000 ; RET X17 ; NOP
        assert_eq!(buf[0], 0x58000051);
        assert_eq!(buf[1], 0x14000003);
        assert_eq!(buf[2], 0x4000);
        assert_eq!(buf[3], 0);
        assert_eq!(buf[4], 0xD65F0220);
    }

    #[test]
    fn relo_b_bl_sets_lr() {
        let mut buf = [0u32; 16];
        let n = relo_b(&mut buf, 0x94000000, 0x4000, true, false);
        assert!(n > 0);
        // After the .quad: ADR X30,. ; ADD X30,X30,#12 ; RET X17 ; NOP
        assert_eq!(buf[4], 0x1000001E);
        assert_eq!(buf[5], 0x910033DE);
        assert_eq!(buf[6], 0xD65F0220);
        assert_eq!(buf[7], ARM64_NOP);
    }

    #[test]
    fn relo_bc_conditional() {
        let mut buf = [0u32; 16];
        // B.EQ with cond=0
        let n = relo_b(&mut buf, 0x54000040, 0x4000, false, true);
        assert!(n > 0);
        // First two should be conditional forward skip
        assert_eq!(buf[0] & 0xFF00001F, 0x54000040 & 0xFF00001F);
        assert_eq!(buf[1], 0x14000006); // B #24
    }

    // ---- relo_adr ----

    #[test]
    fn relo_adr_encodes() {
        let mut buf = [0u32; 4];
        relo_adr(&mut buf, 0, 0x1234_5678);
        // LDR X0, #8
        assert_eq!(buf[0], 0x58000040);
        // B #12
        assert_eq!(buf[1], 0x14000003);
        // .quad target
        assert_eq!(buf[2], 0x1234_5678);
        assert_eq!(buf[3], 0);
    }

    // ---- relo_ldr_int ----

    #[test]
    fn relo_ldr_int_32bit() {
        let mut buf = [0u32; 6];
        relo_ldr_int(&mut buf, 0, 0xCAFE, false, false);
        // LDR X0, #12
        assert_eq!(buf[0], 0x58000060);
        // LDR W0, [X0]
        assert_eq!(buf[1], 0xB9400000);
        // B #16
        assert_eq!(buf[2], 0x14000004);
        assert_eq!(buf[3], ARM64_NOP);
    }

    #[test]
    fn relo_ldr_int_64bit() {
        let mut buf = [0u32; 6];
        relo_ldr_int(&mut buf, 0, 0xCAFE, true, false);
        // LDR X0, [X0]
        assert_eq!(buf[1], 0xF9400000);
    }

    #[test]
    fn relo_ldr_int_ldrsw() {
        let mut buf = [0u32; 6];
        relo_ldr_int(&mut buf, 0, 0xCAFE, false, true);
        // LDRSW X0, [X0]
        assert_eq!(buf[1], 0xB9800000);
    }

    // ---- relo_cb ----

    #[test]
    fn relo_cb_encodes() {
        let mut buf = [0u32; 6];
        // CBZ X0, target
        relo_cb(&mut buf, 0x34000020, 0x8000);
        // CBZ X0, #8
        assert_eq!(buf[0] & 0xFF00001F, 0x34000000);
        assert_eq!(buf[1], 0x14000005); // B #20
        assert_eq!(buf[2], 0x58000051); // LDR X17, #8
        assert_eq!(buf[3], 0xD65F0220); // RET X17
        assert_eq!(buf[4], 0x8000); // target low
        assert_eq!(buf[5], 0); // target high
    }

    // ---- relo_tb ----

    #[test]
    fn relo_tb_encodes() {
        let mut buf = [0u32; 6];
        // TBZ X0, #0, target
        relo_tb(&mut buf, 0x36000020, 0x9000);
        // TBZ X0, #0, #8
        assert_eq!(buf[0] & 0xFFF8001F, 0x36000000);
        assert_eq!(buf[1], 0x14000005); // B #20
        assert_eq!(buf[2], 0x58000051); // LDR X17, #8
        assert_eq!(buf[3], 0xD61F0220); // BR X17
        assert_eq!(buf[4], 0x9000);
        assert_eq!(buf[5], 0);
    }

    // ---- relo_ignore ----

    #[test]
    fn relo_ignore_passthrough() {
        let mut buf = [0u32; 2];
        relo_ignore(&mut buf, 0xDEADBEEF);
        assert_eq!(buf[0], 0xDEADBEEF);
        assert_eq!(buf[1], ARM64_NOP);
    }
}
