/// get some bits from n -> [high : low]
/// n must be a u32
pub fn bits32(n: u32, high: u32, low: u32) -> Option<u32> {
    if high < 32 && low < 32 && low < high {
        Some((n << (31 - high)) >> (31 - high + low))
    } else {
        None
    }
}

pub fn bit(n: u32, st: u32) -> u32 {
    (n >> st) & 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits32() {
        assert_eq!(bits32(0x0FFFFF00, 23, 8), Some(0xFFFF));
        assert_eq!(bits32(0x0000FFFF, 15, 0), Some(0xFFFF));
    }

    #[test]
    fn test_bit() {
        assert_eq!(bit(0b010000000, 7), 1);
        assert_eq!(bit(0b1, 0), 1);
    }
}
