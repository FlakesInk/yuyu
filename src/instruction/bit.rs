//! Low-level bit-manipulation utilities used throughout ARM64 instruction
//! encoding / decoding.
//!
//! These are the Rust equivalents of the C preprocessor macros:
//! ```c
//! #define bits32(n, high, low)  ((n) << (31 - high)) >> (31 - high + low)
//! #define bit(n, st)            (((n) >> (st)) & 1)
//! #define sign64_extend(n, len) ...
//! ```

/// Extract bits `[high : low]` from a `u32`.
///
/// Returns `None` if `high >= 32` or `low > high`.
///
/// # Examples
///
/// ```
/// use yuyu::instruction::bit::bits32;
/// assert_eq!(bits32(0x0FFFFF00, 23, 8), Some(0xFFFF));
/// assert_eq!(bits32(0x80000000, 31, 31), Some(1));   // single bit
/// assert_eq!(bits32(0xFF, 0, 5), None);               // low > high
/// ```
#[inline(always)]
pub fn bits32(n: u32, high: u32, low: u32) -> Option<u32> {
    if high < 32 && low <= high {
        Some((n << (31 - high)) >> (31 - high + low))
    } else {
        None
    }
}

/// Extract a single bit at position `st` (0-indexed).
///
/// Returns 0 or 1. The caller must ensure `st < 32`.
///
/// # Examples
///
/// ```
/// use yuyu::instruction::bit::bit;
/// assert_eq!(bit(0b10000000, 7), 1);
/// assert_eq!(bit(0b10000000, 0), 0);
/// ```
#[inline(always)]
pub fn bit(n: u32, st: u32) -> u32 {
    (n >> st) & 1
}

/// Sign-extend a `bits`-bit unsigned value to a full `i64`.
///
/// The input `n` is treated as a `bits`-width two's-complement integer.
///
/// # Examples
///
/// ```
/// use yuyu::instruction::bit::sign_extend;
/// assert_eq!(sign_extend(0b1111, 4), -1);         // 4-bit 0b1111 → -1
/// assert_eq!(sign_extend(0b0111, 4), 7);           // 4-bit 0b0111 → 7
/// assert_eq!(sign_extend(0xFFFFFFF, 28), -1);      // 28-bit all-ones
/// assert_eq!(sign_extend(0x7FFFFFF, 28), 134217727); // 28-bit max positive
/// ```
#[inline(always)]
pub fn sign_extend(n: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((n << shift) as i64) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- bits32 ----

    #[test]
    fn test_bits32_mid_range() {
        assert_eq!(bits32(0x0FFFFF00, 23, 8), Some(0xFFFF));
        assert_eq!(bits32(0x0000FFFF, 15, 0), Some(0xFFFF));
    }

    #[test]
    fn test_bits32_single_bit() {
        assert_eq!(bits32(0x80000000, 31, 31), Some(1));
        assert_eq!(bits32(0x00000001, 0, 0), Some(1));
        assert_eq!(bits32(0x00000000, 5, 5), Some(0));
    }

    #[test]
    fn test_bits32_msb() {
        assert_eq!(bits32(0xFFFFFFFF, 31, 24), Some(0xFF));
        assert_eq!(bits32(0x12345678, 31, 28), Some(0x1));
    }

    #[test]
    fn test_bits32_lsb() {
        assert_eq!(bits32(0x0000000F, 3, 0), Some(0xF));
        assert_eq!(bits32(0x00000001, 0, 0), Some(1));
    }

    #[test]
    fn test_bits32_invalid_low_gt_high() {
        assert_eq!(bits32(0xFF, 0, 5), None);
    }

    #[test]
    fn test_bits32_invalid_high_out_of_range() {
        assert_eq!(bits32(0xFF, 32, 0), None);
        assert_eq!(bits32(0xFF, 100, 50), None);
    }

    // ---- bit ----

    #[test]
    fn test_bit_msb() {
        assert_eq!(bit(0b010000000, 7), 1);
        assert_eq!(bit(0b10000000_00000000_00000000_00000000, 31), 1);
    }

    #[test]
    fn test_bit_lsb() {
        assert_eq!(bit(0b1, 0), 1);
        assert_eq!(bit(0b10, 0), 0);
    }

    #[test]
    fn test_bit_zero() {
        assert_eq!(bit(0x00000000, 15), 0);
        assert_eq!(bit(0xFFFFFFFF, 31), 1);
    }

    // ---- sign_extend ----

    #[test]
    fn test_sign_extend_positive() {
        assert_eq!(sign_extend(0b1111, 4), -1);
        assert_eq!(sign_extend(0b1000, 4), -8);
    }

    #[test]
    fn test_sign_extend_negative() {
        assert_eq!(sign_extend(0b0111, 4), 7);
        assert_eq!(sign_extend(0b0000, 4), 0);
    }

    #[test]
    fn test_sign_extend_large_values() {
        // 28-bit signed value: 0x7FFFFFF → +134217727
        assert_eq!(sign_extend(0x7FFFFFF, 28), 134217727);
        // 28-bit signed value: 0xFFFFFFF → -1
        assert_eq!(sign_extend(0xFFFFFFF, 28), -1);
    }

    #[test]
    fn test_sign_extend_21bit() {
        // 21-bit: 0x100000 → sign bit (bit 20) is 1 → negative
        // Value = -(2^21 - 0x100000) = -(2097152 - 1048576) = -1048576
        assert_eq!(sign_extend(0x100000, 21), -1048576);
        // 21-bit: 0x0FFFFF → bit 20 = 0 → max positive = 2^20 - 1 = 1048575
        assert_eq!(sign_extend(0x0FFFFF, 21), 1048575);
    }
}
