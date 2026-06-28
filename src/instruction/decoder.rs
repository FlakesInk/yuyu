//! ARM64 instruction classification and field extraction.
//!
//! # Overview
//!
//! - [`classify_inst`] identifies an instruction's type (B, BL, ADR, LDR, …)
//!   and returns the number of `u32` words needed to relocate it.
//! - `extract_*` functions pull encoded immediate / register fields from
//!   instruction words.
//! - `compute_*` functions translate PC-relative immediates into absolute
//!   target addresses.
//!
//! # Instruction constants
//!
//! This module also exports ARM64 opcode / mask constants (e.g.
//! [`INST_B`], [`MASK_B`], [`ARM64_NOP`]) used by the writer and reloc
//! modules.

use crate::instruction::bit::{bits32, sign_extend};

/// ARM64 instruction type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InstType {
    /// Unconditional branch: `B <offset>`
    B = 0,
    /// Conditional branch: `B.<cond> <offset>`
    BC = 1,
    /// Branch with link: `BL <offset>`
    BL = 2,
    /// Form PC-relative address: `ADR <Xd>, <label>`
    ADR = 3,
    /// Form PC-relative address to 4KB page: `ADRP <Xd>, <label>`
    ADRP = 4,
    /// Load 32-bit literal: `LDR <Wt>, <label>`
    LDR32 = 5,
    /// Load 64-bit literal: `LDR <Xt>, <label>`
    LDR64 = 6,
    /// Load signed word literal: `LDRSW <Xt>, <label>`
    LDRSWLit = 7,
    /// Prefetch literal: `PRFM <prfop>, <label>`
    PRFMLit = 8,
    /// Load SIMD 32-bit literal
    LDRSimd32 = 9,
    /// Load SIMD 64-bit literal
    LDRSimd64 = 10,
    /// Load SIMD 128-bit literal
    LDRSimd128 = 11,
    /// Compare and branch on zero: `CBZ <Rt>, <label>`
    CBZ = 12,
    /// Compare and branch on non-zero: `CBNZ <Rt>, <label>`
    CBNZ = 13,
    /// Test bit and branch on zero: `TBZ <Rt>, #<imm>, <label>`
    TBZ = 14,
    /// Test bit and branch on non-zero: `TBNZ <Rt>, #<imm>, <label>`
    TBNZ = 15,
    /// Ignored / unrecognized instruction (pass through).
    Ignore = 16,
}

/// Instruction opcode constants (bits 31:24 pattern).
pub const INST_B: u32 = 0x14000000;
pub const INST_BC: u32 = 0x54000000;
pub const INST_BL: u32 = 0x94000000;
pub const INST_ADR: u32 = 0x10000000;
pub const INST_ADRP: u32 = 0x90000000;
pub const INST_LDR_32: u32 = 0x18000000;
pub const INST_LDR_64: u32 = 0x58000000;
pub const INST_LDRSW_LIT: u32 = 0x98000000;
pub const INST_PRFM_LIT: u32 = 0xD8000000;
pub const INST_LDR_SIMD_32: u32 = 0x1C000000;
pub const INST_LDR_SIMD_64: u32 = 0x5C000000;
pub const INST_LDR_SIMD_128: u32 = 0x9C000000;
pub const INST_CBZ: u32 = 0x34000000;
pub const INST_CBNZ: u32 = 0x35000000;
pub const INST_TBZ: u32 = 0x36000000;
pub const INST_TBNZ: u32 = 0x37000000;

/// Instruction mask constants (which bits matter for classification).
pub const MASK_B: u32 = 0xFC000000;
pub const MASK_BC: u32 = 0xFF000010;
pub const MASK_BL: u32 = 0xFC000000;
pub const MASK_ADR: u32 = 0x9F000000;
pub const MASK_ADRP: u32 = 0x9F000000;
pub const MASK_LDR_32: u32 = 0xFF000000;
pub const MASK_LDR_64: u32 = 0xFF000000;
pub const MASK_LDRSW_LIT: u32 = 0xFF000000;
pub const MASK_PRFM_LIT: u32 = 0xFF000000;
pub const MASK_LDR_SIMD_32: u32 = 0xFF000000;
pub const MASK_LDR_SIMD_64: u32 = 0xFF000000;
pub const MASK_LDR_SIMD_128: u32 = 0xFF000000;
pub const MASK_CBZ: u32 = 0x7F000000;
pub const MASK_CBNZ: u32 = 0x7F000000;
pub const MASK_TBZ: u32 = 0x7F000000;
pub const MASK_TBNZ: u32 = 0x7F000000;

/// Special ARM64 instructions.
pub const ARM64_NOP: u32 = 0xD503201F;
pub const ARM64_HINT: u32 = 0xD503201F;
pub const ARM64_PACIASP: u32 = 0xD503233F;
pub const ARM64_PACIBSP: u32 = 0xD503237F;
pub const ARM64_BTI_C: u32 = 0xD503245F;
pub const ARM64_BTI_J: u32 = 0xD503249F;
pub const ARM64_BTI_JC: u32 = 0xD50324DF;

/// Lookup table: matching masks for each instruction type.
static MASKS: [u32; 17] = [
    MASK_B,
    MASK_BC,
    MASK_BL,
    MASK_ADR,
    MASK_ADRP,
    MASK_LDR_32,
    MASK_LDR_64,
    MASK_LDRSW_LIT,
    MASK_PRFM_LIT,
    MASK_LDR_SIMD_32,
    MASK_LDR_SIMD_64,
    MASK_LDR_SIMD_128,
    MASK_CBZ,
    MASK_CBNZ,
    MASK_TBZ,
    MASK_TBNZ,
    0, // IGNORE
];

/// Lookup table: opcode patterns for each instruction type.
static TYPES: [u32; 17] = [
    INST_B,
    INST_BC,
    INST_BL,
    INST_ADR,
    INST_ADRP,
    INST_LDR_32,
    INST_LDR_64,
    INST_LDRSW_LIT,
    INST_PRFM_LIT,
    INST_LDR_SIMD_32,
    INST_LDR_SIMD_64,
    INST_LDR_SIMD_128,
    INST_CBZ,
    INST_CBNZ,
    INST_TBZ,
    INST_TBNZ,
    0, // IGNORE
];

/// Number of 4-byte slots required for the relocated version of each instruction type.
pub static RELO_LEN: [usize; 17] = [6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2];

/// Classify a raw instruction word into its type, and return the length of
/// its relocation sequence (number of `u32` words).
///
/// # Examples
///
/// ```
/// use yuyu::instruction::decoder::{classify_inst, InstType};
/// assert_eq!(classify_inst(0x14000004), (InstType::B, 6));
/// assert_eq!(classify_inst(0xD503201F), (InstType::Ignore, 2)); // NOP
/// ```
#[inline]
pub fn classify_inst(inst: u32) -> (InstType, usize) {
    for i in 0..MASKS.len() {
        if (inst & MASKS[i]) == TYPES[i] {
            // SAFETY: i is guaranteed to be within the InstType enum range.
            let ty = unsafe { std::mem::transmute::<u32, InstType>(i as u32) };
            return (ty, RELO_LEN[i]);
        }
    }
    (InstType::Ignore, RELO_LEN[16])
}

/// Extract the signed 64-bit immediate offset from a B / BL instruction.
/// - For B/BL: imm26 at bits `[25:0]`, scaled by 4, sign-extended to 28 bits.
pub fn extract_b_imm(inst: u32) -> i64 {
    let imm26 = bits32(inst, 25, 0).unwrap_or(0) as u64;
    sign_extend(imm26 << 2, 28)
}

/// Extract the signed 64-bit immediate offset from a BC instruction.
/// - For BC: imm19 at bits `[23:5]`, scaled by 4, sign-extended to 21 bits.
pub fn extract_bc_imm(inst: u32) -> i64 {
    let imm19 = bits32(inst, 23, 5).unwrap_or(0) as u64;
    sign_extend(imm19 << 2, 21)
}

/// Extract destination register index (bits `[4:0]`).
pub fn extract_rd(inst: u32) -> u32 {
    bits32(inst, 4, 0).unwrap_or(0)
}

/// Extract the immediate fields for ADR instruction.
/// Returns (immlo, immhi).
pub fn extract_adr_imm(inst: u32) -> (u64, u64) {
    let immlo = bits32(inst, 30, 29).unwrap_or(0) as u64;
    let immhi = bits32(inst, 23, 5).unwrap_or(0) as u64;
    (immlo, immhi)
}

/// Compute the target address for an ADR instruction.
pub fn compute_adr_target(inst_addr: u64, immhi: u64, immlo: u64) -> u64 {
    let offset = sign_extend((immhi << 2) | immlo, 21);
    (inst_addr as i64).wrapping_add(offset) as u64
}

/// Compute the target address for an ADRP instruction.
pub fn compute_adrp_target(inst_addr: u64, immhi: u64, immlo: u64) -> u64 {
    let offset = sign_extend((immhi << 14) | (immlo << 12), 33);
    let addr = (inst_addr as i64).wrapping_add(offset) as u64;
    addr & 0xFFFF_FFFF_FFFF_F000
}

/// Extract the 19-bit immediate from LDR literal / CBZ / CBNZ (bits `[23:5]`).
pub fn extract_imm19(inst: u32) -> u64 {
    bits32(inst, 23, 5).unwrap_or(0) as u64
}

/// Compute the target address for an LDR literal instruction.
pub fn compute_ldr_target(inst_addr: u64, imm19: u64) -> u64 {
    let offset = sign_extend(imm19 << 2, 21);
    (inst_addr as i64).wrapping_add(offset) as u64
}

/// Extract the 14-bit immediate from TBZ / TBNZ (bits `[18:5]`).
pub fn extract_imm14(inst: u32) -> u64 {
    bits32(inst, 18, 5).unwrap_or(0) as u64
}

/// Compute the target address for a TBZ/TBNZ instruction.
pub fn compute_tb_target(inst_addr: u64, imm14: u64) -> u64 {
    let offset = sign_extend(imm14 << 2, 16);
    (inst_addr as i64).wrapping_add(offset) as u64
}

/// Compute the target address for a CBZ/CBNZ instruction.
pub fn compute_cb_target(inst_addr: u64, imm19: u64) -> u64 {
    compute_ldr_target(inst_addr, imm19)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- classify_inst ----

    #[test]
    fn classify_b() {
        // B #4  (imm26=1, scaled=4)
        let inst = 0x14000001;
        assert_eq!(classify_inst(inst), (InstType::B, 6));
    }

    #[test]
    fn classify_bl() {
        // BL #0
        let inst = 0x94000000;
        assert_eq!(classify_inst(inst), (InstType::BL, 8));
    }

    #[test]
    fn classify_bc() {
        // B.EQ #4
        let inst = 0x54000040;
        assert_eq!(classify_inst(inst), (InstType::BC, 8));
    }

    #[test]
    fn classify_adr() {
        // ADR X0, .
        let inst = 0x10000000;
        assert_eq!(classify_inst(inst), (InstType::ADR, 4));
    }

    #[test]
    fn classify_adrp() {
        // ADRP X0, .
        let inst = 0x90000000;
        assert_eq!(classify_inst(inst), (InstType::ADRP, 4));
    }

    #[test]
    fn classify_ldr32() {
        // LDR W0, .
        let inst = 0x18000000;
        assert_eq!(classify_inst(inst), (InstType::LDR32, 6));
    }

    #[test]
    fn classify_ldr64() {
        // LDR X0, .
        let inst = 0x58000000;
        assert_eq!(classify_inst(inst), (InstType::LDR64, 6));
    }

    #[test]
    fn classify_cbz() {
        // CBZ X0, #4
        let inst = 0x34000020;
        assert_eq!(classify_inst(inst), (InstType::CBZ, 6));
    }

    #[test]
    fn classify_cbnz() {
        // CBNZ X0, #4
        let inst = 0x35000020;
        assert_eq!(classify_inst(inst), (InstType::CBNZ, 6));
    }

    #[test]
    fn classify_tbz() {
        // TBZ X0, #0, #4
        let inst = 0x36000020;
        assert_eq!(classify_inst(inst), (InstType::TBZ, 6));
    }

    #[test]
    fn classify_tbnz() {
        // TBNZ X0, #0, #4
        let inst = 0x37000020;
        assert_eq!(classify_inst(inst), (InstType::TBNZ, 6));
    }

    #[test]
    fn classify_nop_is_ignore() {
        // NOP (not in the classify table, so falls back to Ignore)
        let inst = 0xD503201F;
        assert_eq!(classify_inst(inst), (InstType::Ignore, 2));
    }

    // ---- extract_b_imm ----

    #[test]
    fn extract_b_forward() {
        // B #0x10  (imm26=4, scale → offset=16)
        let inst = 0x14000004;
        assert_eq!(extract_b_imm(inst), 16);
    }

    #[test]
    fn extract_b_backward() {
        // B #-4: imm26 = -1 (two's complement) = 0x3FFFFFF
        // Instruction = 0x14000000 | 0x3FFFFFF = 0x17FFFFFF
        let inst = 0x17FFFFFF;
        assert_eq!(extract_b_imm(inst), -4);
    }

    // ---- extract_bc_imm ----

    #[test]
    fn extract_bc_forward() {
        // B.EQ #8  (imm19=1, scale → offset=4... wait imm19=2 gives offset=8)
        // Actually B.EQ #8: bit[23:5]=0b10 → imm19=2, scaled by 4 → 8
        let inst = 0x54000040;
        assert_eq!(extract_bc_imm(inst), 8);
    }

    // ---- compute_adr_target ----

    #[test]
    fn compute_adr_target_at_zero() {
        // ADR X0, #0  (no offset)
        // immhi=0, immlo=0 → offset=0
        assert_eq!(compute_adr_target(0x1000, 0, 0), 0x1000);
    }

    #[test]
    fn compute_adr_target_forward() {
        // ADR X0, #4  (immlo=1, immhi=0 → offset=1)
        assert_eq!(compute_adr_target(0x1000, 0, 1), 0x1001);
    }

    // ---- compute_adrp_target ----

    #[test]
    fn compute_adrp_page() {
        // ADRP X0, #0  at address 0x1000 → page 0x1000
        assert_eq!(compute_adrp_target(0x1000, 0, 0), 0x1000);
    }

    // ---- extract_rd ----

    #[test]
    fn extract_rd_x0() {
        assert_eq!(extract_rd(0x00000000), 0);
    }

    #[test]
    fn extract_rd_x17() {
        // Rt=17 in bits [4:0]
        assert_eq!(extract_rd(0x00000011), 17);
    }

    // ---- extract_imm19 ----

    #[test]
    fn extract_imm19_value() {
        // Create a pattern: imm19 = 0x12345 at bits [23:5]
        // (0x12345 << 5) = 0x2468A0
        let inst = 0x58000000 | (0x12345 << 5);
        assert_eq!(extract_imm19(inst), 0x12345);
    }

    // ---- extract_imm14 ----

    #[test]
    fn extract_imm14_value() {
        // imm14 = 0xABC at bits [18:5]
        let inst = 0x36000000 | (0xABC << 5);
        assert_eq!(extract_imm14(inst), 0xABC);
    }

    // ---- ARM64 hint constants ----

    #[test]
    fn bti_c_is_hint() {
        // BTI_C must match the instruction encoding
        assert_eq!(ARM64_BTI_C, 0xD503245F);
    }

    #[test]
    fn nop_is_correct() {
        assert_eq!(ARM64_NOP, 0xD503201F);
    }

    #[test]
    fn paciasp_is_correct() {
        assert_eq!(ARM64_PACIASP, 0xD503233F);
    }
}
