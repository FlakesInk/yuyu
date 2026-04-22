const B_REL_RANGE: usize = (1 << 25) << 2;
const ARM64_NOP: u32 = 0xd503201f;

fn can_be_rel(src: usize, dst: usize) -> bool {
    if dst >= src {
        (dst - src) <= B_REL_RANGE
    } else {
        (src - dst) <= B_REL_RANGE
    }
}

fn branch_relative(src: usize, dst: usize) -> Option<Vec<u32>> {
    if can_be_rel(src, dst) {
        let diff = (dst as i64).wrapping_sub(src as i64);
        Some(vec![
            0x14000000u32 | (diff & 0x0FFFFFFF >> 2) as u32, // B <label>
            ARM64_NOP,
        ])
    } else {
        None
    }
}
fn branch_absolute(addr: usize) -> Vec<u32> {
    vec![
        0x58000051, // LDR X17, #8
        0xd61f0220, // BR X17
        addr as u32,
        (addr >> 32) as u32,
    ]
}

pub fn ret_absolute(addr: usize) -> Vec<u32> {
    vec![
        0x58000051, // LDR X17, #8
        0xd65f0220, // RET X17
        addr as u32,
        (addr >> 32) as u32,
    ]
}
pub fn branch_from_to(src: usize, dst: usize) -> Vec<u32> {
    if let Some(buf) = branch_relative(src, dst) {
        buf
    } else {
        ret_absolute(dst)
    }
}
