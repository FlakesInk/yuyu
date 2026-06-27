//! Instruction relocation — generates replacement instruction sequences
//! for instructions that are overwritten by a hook trampoline.
//!
//! When a hook overwrites the first N instructions at the origin address,
//! those instructions must be "relocated" so they can still execute from
//! a different address. This module handles classifying each overwritten
//! instruction and producing the corresponding relocated code in the
//! hook's `relo_insts` buffer.

use crate::error::{HookError, HookResult};
use crate::hook::context::{Hook, TRAMPOLINE_MAX_NUM};
use crate::instruction::decoder::{self, InstType, classify_inst};
use crate::instruction::writer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check whether an address falls within the original trampoline region.
fn is_in_tramp(origin_addr: u64, tramp_insts_num: i32, addr: u64) -> bool {
    let tramp_start = origin_addr;
    let tramp_end = tramp_start + tramp_insts_num as u64 * 4;
    addr >= tramp_start && addr < tramp_end
}

/// Given an address that may fall inside the trampoline, compute the
/// corresponding relocated address in the relo buffer.
fn relo_in_tramp(
    origin_addr: u64,
    tramp_insts_num: i32,
    origin_insts: &[u32; TRAMPOLINE_MAX_NUM],
    relo_addr: u64,
    addr: u64,
) -> u64 {
    let tramp_start = origin_addr;
    let tramp_end = tramp_start + tramp_insts_num as u64 * 4;
    if !(addr >= tramp_start && addr < tramp_end) {
        return addr;
    }
    let addr_inst_index = ((addr - tramp_start) / 4) as usize;
    let mut fix_addr = relo_addr;
    for &inst in origin_insts.iter().take(addr_inst_index) {
        let (_, len) = classify_inst(inst);
        fix_addr += (len * 4) as u64;
    }
    fix_addr
}

// ---------------------------------------------------------------------------
// Main relocation entry point
// ---------------------------------------------------------------------------

/// Write relocated instructions for a single original instruction at
/// `inst_addr` into the hook's `relo_insts` buffer.
///
/// Advances `hook.relo_insts_num` by the number of u32 words written.
#[inline(never)]
pub fn relocate_inst(hook: &mut Hook, inst_addr: u64, inst: u32) -> HookResult<()> {
    let (it, len) = classify_inst(inst);

    // Extract fields we'll need from hook before borrowing relo_insts
    let origin_addr = hook.origin_addr;
    let tramp_insts_num = hook.tramp_insts_num;
    let relo_addr = hook.relo_addr;

    let buf_start = hook.relo_insts_num as usize;
    let buf = &mut hook.relo_insts[buf_start..];

    match it {
        InstType::B | InstType::BC | InstType::BL => {
            let (imm, is_bl, is_bc) = match it {
                InstType::BC => (decoder::extract_bc_imm(inst) as u64, false, true),
                InstType::BL => (decoder::extract_b_imm(inst) as u64, true, false),
                _ => (decoder::extract_b_imm(inst) as u64, false, false),
            };
            let target = (inst_addr as i64).wrapping_add(imm as i64) as u64;
            let target = relo_in_tramp(
                origin_addr,
                tramp_insts_num,
                &hook.origin_insts,
                relo_addr,
                target,
            );
            let _ = writer::relo_b(buf, inst, target, is_bl, is_bc);
        }
        InstType::ADR | InstType::ADRP => {
            let rd = decoder::extract_rd(inst);
            let (immlo, immhi) = decoder::extract_adr_imm(inst);
            let target = if it == InstType::ADR {
                decoder::compute_adr_target(inst_addr, immhi, immlo)
            } else {
                let addr = decoder::compute_adrp_target(inst_addr, immhi, immlo);
                if is_in_tramp(origin_addr, tramp_insts_num, addr) {
                    return Err(HookError::BadRelo);
                }
                addr
            };
            writer::relo_adr(buf, rd, target);
        }
        InstType::LDR32
        | InstType::LDR64
        | InstType::LDRSWLit
        | InstType::PRFMLit
        | InstType::LDRSimd32
        | InstType::LDRSimd64
        | InstType::LDRSimd128 => {
            let rt = decoder::extract_rd(inst);
            let imm19 = decoder::extract_imm19(inst);
            let target = decoder::compute_ldr_target(inst_addr, imm19);

            if is_in_tramp(origin_addr, tramp_insts_num, target) && it != InstType::PRFMLit {
                return Err(HookError::BadRelo);
            }
            let target = relo_in_tramp(
                origin_addr,
                tramp_insts_num,
                &hook.origin_insts,
                relo_addr,
                target,
            );

            match it {
                InstType::LDR32 | InstType::LDR64 | InstType::LDRSWLit => {
                    let is_64bit = it == InstType::LDR64;
                    let is_ldrsw = it == InstType::LDRSWLit;
                    writer::relo_ldr_int(buf, rt, target, is_64bit, is_ldrsw);
                }
                _ => {
                    let simd_type: u8 = match it {
                        InstType::PRFMLit => 0,
                        InstType::LDRSimd32 => 1,
                        InstType::LDRSimd64 => 2,
                        _ => 3,
                    };
                    writer::relo_ldr_simd(buf, rt, target, simd_type);
                }
            }
        }
        InstType::CBZ | InstType::CBNZ => {
            let imm19 = decoder::extract_imm19(inst);
            let target = decoder::compute_cb_target(inst_addr, imm19);
            let target = relo_in_tramp(
                origin_addr,
                tramp_insts_num,
                &hook.origin_insts,
                relo_addr,
                target,
            );
            writer::relo_cb(buf, inst, target);
        }
        InstType::TBZ | InstType::TBNZ => {
            let imm14 = decoder::extract_imm14(inst);
            let target = decoder::compute_tb_target(inst_addr, imm14);
            let target = relo_in_tramp(
                origin_addr,
                tramp_insts_num,
                &hook.origin_insts,
                relo_addr,
                target,
            );
            writer::relo_tb(buf, inst, target);
        }
        InstType::Ignore => {
            writer::relo_ignore(buf, inst);
        }
    }

    hook.relo_insts_num += len as i32;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Hook for testing relocation helpers.
    fn make_test_hook() -> Hook {
        Hook {
            origin_addr: 0x1000,
            tramp_insts_num: 4,
            relo_addr: 0x2000,
            origin_insts: [
                0x14000000,                             // B #0 → (B, 6)
                crate::instruction::decoder::ARM64_NOP, // NOP → (Ignore, 2)
                0x10000000,                             // ADR X0,. → (ADR, 4)
                0,
                0,
                0,
            ],
            ..Default::default()
        }
    }

    #[test]
    fn is_in_tramp_inside() {
        // origin=0x1000, tramp=4 instructions (16 bytes)
        assert!(is_in_tramp(0x1000, 4, 0x1000));
        assert!(is_in_tramp(0x1000, 4, 0x1004));
        assert!(is_in_tramp(0x1000, 4, 0x100C));
    }

    #[test]
    fn is_in_tramp_outside() {
        assert!(!is_in_tramp(0x1000, 4, 0x0FFC));
        assert!(!is_in_tramp(0x1000, 4, 0x1010));
    }

    #[test]
    fn relo_in_tramp_outside_returns_original() {
        let hook = make_test_hook();
        // Address outside trampoline → returned unchanged
        assert_eq!(
            relo_in_tramp(
                hook.origin_addr,
                hook.tramp_insts_num,
                &hook.origin_insts,
                hook.relo_addr,
                0x5000
            ),
            0x5000
        );
    }

    #[test]
    fn relo_in_tramp_first_instruction() {
        let hook = make_test_hook();
        // First trampoline instruction is at offset 0 → relo base = 0x2000
        assert_eq!(
            relo_in_tramp(
                hook.origin_addr,
                hook.tramp_insts_num,
                &hook.origin_insts,
                hook.relo_addr,
                0x1000
            ),
            0x2000
        );
    }

    #[test]
    fn relo_in_tramp_second_instruction() {
        let hook = make_test_hook();
        // Second trampoline instruction:
        // inst[0] = B → relo_len=6 → 6*4=24 bytes
        // So inst[1] relocated at 0x2000 + 24 = 0x2018
        assert_eq!(
            relo_in_tramp(
                hook.origin_addr,
                hook.tramp_insts_num,
                &hook.origin_insts,
                hook.relo_addr,
                0x1004
            ),
            0x2018
        );
    }

    #[test]
    fn relo_in_tramp_third_instruction() {
        let hook = make_test_hook();
        // inst[0] = B → 6 words (24 bytes)
        // inst[1] = NOP → 2 words (8 bytes)
        // inst[2] at offset: 0x2000 + 24 + 8 = 0x2020
        assert_eq!(
            relo_in_tramp(
                hook.origin_addr,
                hook.tramp_insts_num,
                &hook.origin_insts,
                hook.relo_addr,
                0x1008
            ),
            0x2020
        );
    }
}
