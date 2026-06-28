//! Signature (pattern) scanning for readable memory regions.
//!
//! Provides AOB (Array of Bytes) style pattern searching across readable
//! memory mappings. Useful for locating functions or data by their binary
//! fingerprint when symbol information is unavailable.
//!
//! # Scanning scope
//!
//! | Function | Scope |
//! |----------|-------|
//! | [`sig_scan`] | All readable regions in `/proc/self/maps` |
//! | [`sig_scan_module`] | Readable regions whose pathname contains a given string |
//! | [`sig_scan_range`] | A caller-specified `[addr, addr+size)` interval (unsafe) |
//! | [`sig_scan_all`] | Same as [`sig_scan`], but returns every match |
//!
//! # Pattern format
//!
//! Patterns are specified as hex byte strings with `??` or `?` as wildcards:
//!
//! ```text
//! "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??"   // full-byte wildcards
//! "FF 43 01 D6"                             // exact match (no wildcards)
//! "?A"                                       // nibble wildcard (matches 0A..FA)
//! ```
//!
//! - Tokens are separated by whitespace.
//! - `??` matches any single byte (both nibbles wild).
//! - `XX` matches an exact byte.
//! - `X?` or `?X` — one nibble wild, one nibble exact.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::str::FromStr;
//! use yuyu::memory::sigscan::{Signature, sig_scan, sig_scan_module};
//!
//! // Search all readable memory
//! let sig = Signature::from_str("FD 7B BF A9 FD 03 00 91").unwrap();
//! if let Some(addr) = sig_scan(&sig) {
//!     println!("Found at 0x{:X}", addr);
//! }
//!
//! // Search within a specific library
//! if let Some(addr) = sig_scan_module(&sig, "libc.so") {
//!     println!("Found in libc at 0x{:X}", addr);
//! }
//! ```

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Fault-safe scanning support
// ---------------------------------------------------------------------------

/// Jump buffer type matching glibc's `jmp_buf`.
/// On AArch64 Linux glibc, `__jmp_buf` is 22 × u64. We oversize for safety.
#[repr(C)]
struct JmpBuf([u64; 64]);

// glibc's `setjmp` is a macro expanding to `_setjmp` (no signal mask)
// or `__sigsetjmp` (saves signal mask). We use the underscore variant.
unsafe extern "C" {
    fn _setjmp(env: *mut JmpBuf) -> libc::c_int;
    fn _longjmp(env: *mut JmpBuf, val: libc::c_int) -> !;
}

/// Set to `true` when a SIGBUS/SIGSEGV is caught during a scan.
static FAULT_OCCURRED: AtomicBool = AtomicBool::new(false);

/// Pointer to the current jump buffer (null when not scanning).
static mut JUMP_BUF: *mut JmpBuf = std::ptr::null_mut();

/// Signal handler that longjmps out of a faulting scan.
extern "C" fn fault_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    FAULT_OCCURRED.store(true, Ordering::SeqCst);
    let jb = unsafe { JUMP_BUF };
    if !jb.is_null() {
        unsafe { _longjmp(jb, 1) };
    }
}

/// Install the fault handler (idempotent — runs at most once).
fn install_fault_handler() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = fault_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER | libc::SA_RESTART;
        unsafe {
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
        }
    });
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// A parsed signature pattern for memory scanning.
///
/// Each byte is stored with two independent nibble masks:
/// - `mask_hi[i]` — `true` if the upper nibble of byte `i` must match.
/// - `mask_lo[i]` — `true` if the lower nibble of byte `i` must match.
///
/// A full-byte wildcard (`??`) clears both masks; an exact byte (`XX`) sets
/// both; a nibble wildcard (`?X` or `X?`) sets only one.
#[derive(Clone)]
pub struct Signature {
    bytes: Vec<u8>,
    mask_hi: Vec<bool>,
    mask_lo: Vec<bool>,
}

impl FromStr for Signature {
    type Err = SigScanError;

    /// Parse a pattern string into a [`Signature`].
    ///
    /// # Format
    ///
    /// Hex tokens separated by whitespace. Supported token forms:
    ///
    /// | Token   | Meaning                          |
    /// |---------|----------------------------------|
    /// | `??`    | Full-byte wildcard               |
    /// | `XX`    | Exact byte (two hex digits)      |
    /// | `X?`    | Upper nibble exact, lower wild   |
    /// | `?X`    | Upper nibble wild, lower exact   |
    ///
    /// # Errors
    ///
    /// Returns [`SigScanError::InvalidPattern`] if the string contains
    /// non-hex characters, malformed tokens, or an odd number of nibbles
    /// (stray `?`).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use yuyu::memory::sigscan::Signature;
    ///
    /// let sig = Signature::from_str("48 8B 05 ?? ?? ?? ?? 48 85 C0").unwrap();
    /// assert_eq!(sig.len(), 10);
    /// ```
    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        let mut bytes = Vec::new();
        let mut mask_hi = Vec::new();
        let mut mask_lo = Vec::new();

        // Collect all nibble-sized tokens, expanding multi-char tokens
        let mut nibbles: Vec<NibbleToken> = Vec::new();

        for token in pattern.split_whitespace() {
            match token {
                "?" => nibbles.push(NibbleToken::Wild),
                "??" => {
                    nibbles.push(NibbleToken::Wild);
                    nibbles.push(NibbleToken::Wild);
                }
                other => {
                    let chars: Vec<char> = other.chars().collect();
                    if chars.len() != 2 {
                        return Err(SigScanError::InvalidPattern);
                    }
                    for &c in &chars {
                        match c {
                            '?' => nibbles.push(NibbleToken::Wild),
                            '0'..='9' | 'a'..='f' | 'A'..='F' => {
                                let val = c.to_digit(16).unwrap() as u8;
                                nibbles.push(NibbleToken::Exact(val));
                            }
                            _ => return Err(SigScanError::InvalidPattern),
                        }
                    }
                }
            }
        }

        // Pair nibbles into bytes
        if !nibbles.len().is_multiple_of(2) {
            return Err(SigScanError::InvalidPattern);
        }

        for chunk in nibbles.chunks(2) {
            let (hi, lo) = (chunk[0], chunk[1]);
            let (hi_val, hi_mask) = match hi {
                NibbleToken::Exact(v) => (v, true),
                NibbleToken::Wild => (0, false),
            };
            let (lo_val, lo_mask) = match lo {
                NibbleToken::Exact(v) => (v, true),
                NibbleToken::Wild => (0, false),
            };
            bytes.push((hi_val << 4) | lo_val);
            mask_hi.push(hi_mask);
            mask_lo.push(lo_mask);
        }

        Ok(Signature {
            bytes,
            mask_hi,
            mask_lo,
        })
    }
}

impl Signature {
    /// Number of bytes in the pattern.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Raw pattern bytes (wildcard nibbles are zero).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Upper-nibble mask: `true` where that nibble must match.
    pub fn mask_hi(&self) -> &[bool] {
        &self.mask_hi
    }

    /// Lower-nibble mask: `true` where that nibble must match.
    pub fn mask_lo(&self) -> &[bool] {
        &self.mask_lo
    }

    /// Check whether the signature matches the memory at `addr`.
    ///
    /// # Safety
    ///
    /// `addr` must point to at least `self.len()` bytes of readable memory.
    pub unsafe fn matches_at(&self, addr: *const u8) -> bool {
        let n = self.bytes.len();
        for i in 0..n {
            let expected = self.bytes[i];
            let actual = unsafe { *addr.add(i) };
            let hi_match = !self.mask_hi[i] || (expected & 0xF0) == (actual & 0xF0);
            let lo_match = !self.mask_lo[i] || (expected & 0x0F) == (actual & 0x0F);
            if !hi_match || !lo_match {
                return false;
            }
        }
        true
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(\"")?;
        for i in 0..self.bytes.len() {
            if i > 0 {
                write!(f, " ")?;
            }
            match (self.mask_hi[i], self.mask_lo[i]) {
                (true, true) => write!(f, "{:02X}", self.bytes[i])?,
                (false, false) => write!(f, "??")?,
                (true, false) => write!(f, "{:01X}?", self.bytes[i] >> 4)?,
                (false, true) => write!(f, "?{:01X}", self.bytes[i] & 0x0F)?,
            }
        }
        write!(f, "\")")
    }
}

/// Internal token used during parsing.
#[derive(Debug, Clone, Copy)]
enum NibbleToken {
    Exact(u8),
    Wild,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during signature scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigScanError {
    /// The pattern string could not be parsed.
    InvalidPattern,
    /// No readable memory regions were found for the process.
    NoReadableMemory,
}

impl fmt::Display for SigScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigScanError::InvalidPattern => write!(f, "invalid signature pattern"),
            SigScanError::NoReadableMemory => write!(f, "no readable memory regions found"),
        }
    }
}

impl std::error::Error for SigScanError {}

// ---------------------------------------------------------------------------
// Memory region enumeration
// ---------------------------------------------------------------------------

/// A readable memory region descriptor.
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// Start address of the region.
    pub start: usize,
    /// Size of the region in bytes.
    pub size: usize,
    /// Pathname (e.g., library/module name), if available.
    pub pathname: Option<String>,
}

/// Enumerate all readable memory regions of the current process.
fn readable_regions() -> Result<Vec<MemRegion>, SigScanError> {
    let maps = proc_maps::get_process_maps(unsafe { libc::getpid() } as _)
        .map_err(|_| SigScanError::NoReadableMemory)?;

    let regions: Vec<MemRegion> = maps
        .iter()
        .filter(|m| m.is_read())
        .map(|m| MemRegion {
            start: m.start(),
            size: m.size(),
            pathname: m.filename().map(|f| f.to_string_lossy().into_owned()),
        })
        .collect();

    if regions.is_empty() {
        return Err(SigScanError::NoReadableMemory);
    }

    Ok(regions)
}

// ---------------------------------------------------------------------------
// Scanning functions
// ---------------------------------------------------------------------------

/// Raw scan — assumes the range is fully readable. Fast path.
///
/// # Safety
///
/// The range `[start, start + size)` must be valid readable memory.
unsafe fn scan_region(sig: &Signature, start: usize, size: usize) -> Option<usize> {
    if sig.is_empty() || size < sig.len() {
        return None;
    }

    let end = start + size - sig.len();
    let mut cur = start;

    while cur <= end {
        if unsafe { sig.matches_at(cur as *const u8) } {
            return Some(cur);
        }
        cur += 1;
    }

    None
}

/// Fault-safe version of [`scan_region`].
///
/// Installs a signal handler for SIGBUS/SIGSEGV that recovers via `siglongjmp`
/// if the region turns out to be inaccessible despite being marked readable
/// in `/proc/self/maps`. Returns `None` when a fault occurs.
fn scan_region_safe(sig: &Signature, start: usize, size: usize) -> Option<usize> {
    if sig.is_empty() || size < sig.len() {
        return None;
    }

    install_fault_handler();
    FAULT_OCCURRED.store(false, Ordering::SeqCst);

    let mut jb: JmpBuf = JmpBuf([0; 64]);
    let old_jb = unsafe { JUMP_BUF };
    unsafe {
        JUMP_BUF = &mut jb as *mut _;
    }

    let result = unsafe {
        if _setjmp(&mut jb as *mut _) == 0 {
            // Normal path: try to scan
            scan_region(sig, start, size)
        } else {
            // Fault path: _longjmp returns here
            None
        }
    };

    // Restore previous jump buffer
    unsafe {
        JUMP_BUF = old_jb;
    }

    result
}

/// Search for the first match across **all readable memory** of the current
/// process.
///
/// # Scope
///
/// Iterates every region in `/proc/self/maps` that has read permission,
/// in address order. This covers:
/// - The executable itself (`.text`, `.rodata`, `.data`, …)
/// - All loaded shared libraries
/// - Stack, heap, and anonymous mappings
/// - `[vvar]`, `[vdso]`, `[vsyscall]`
///
/// Returns the first matching virtual address, or `None`.
///
/// # Example
///
/// ```rust,no_run
/// use std::str::FromStr;
/// use yuyu::memory::sigscan::{Signature, sig_scan};
///
/// let sig = Signature::from_str("FD 7B BF A9").unwrap();
/// if let Some(addr) = sig_scan(&sig) {
///     println!("Pattern found at 0x{:X}", addr);
/// }
/// ```
pub fn sig_scan(sig: &Signature) -> Option<usize> {
    let regions = readable_regions().ok()?;

    for region in &regions {
        if let Some(addr) = scan_region_safe(sig, region.start, region.size) {
            return Some(addr);
        }
    }

    None
}

/// Search for the first match within readable regions whose pathname
/// contains `module_name` (case-insensitive substring match).
///
/// # Scope
///
/// Like [`sig_scan`], but filters `/proc/self/maps` to regions where the
/// pathname column contains the given string. For example:
/// - `"libc"` matches `/usr/lib/aarch64-linux-gnu/libc.so.6`
/// - `"sigscan"` matches the current example binary
/// - `"[stack]"` matches only the main thread stack
///
/// # Example
///
/// ```rust,no_run
/// use std::str::FromStr;
/// use yuyu::memory::sigscan::{Signature, sig_scan_module};
///
/// let sig = Signature::from_str("FD 7B BF A9 FD 03 00 91").unwrap();
/// if let Some(addr) = sig_scan_module(&sig, "libc.so") {
///     println!("Found in libc at 0x{:X}", addr);
/// }
/// ```
pub fn sig_scan_module(sig: &Signature, module_name: &str) -> Option<usize> {
    let regions = readable_regions().ok()?;
    let needle = module_name.to_lowercase();

    for region in &regions {
        let matches = region
            .pathname
            .as_ref()
            .is_some_and(|p| p.to_lowercase().contains(&needle));

        if matches && let Some(addr) = scan_region_safe(sig, region.start, region.size) {
            return Some(addr);
        }
    }

    None
}

/// Search within a **caller-specified address range**.
///
/// # Scope
///
/// Only the exact interval `[start, start + size)` is scanned — no
/// `/proc/self/maps` lookup is performed. The caller is responsible for
/// ensuring the range is valid readable memory.
///
/// # Safety
///
/// The caller must ensure `[start, start + size)` is mapped and readable.
/// This function performs raw pointer reads without signal-handler
/// protection (unlike [`sig_scan`] / [`sig_scan_module`]).
///
/// # Example
///
/// ```rust,no_run
/// use std::str::FromStr;
/// use yuyu::memory::sigscan::{Signature, sig_scan_range};
///
/// let sig = Signature::from_str("FD 7B BF A9").unwrap();
/// // Search within a known 4 KiB range
/// if let Some(addr) = unsafe { sig_scan_range(&sig, 0x7f000000, 0x1000) } {
///     println!("Found at 0x{:X}", addr);
/// }
/// ```
pub unsafe fn sig_scan_range(sig: &Signature, start: usize, size: usize) -> Option<usize> {
    unsafe { scan_region(sig, start, size) }
}

/// Search for **all** matches across all readable memory of the current
/// process.
///
/// # Scope
///
/// Same scope as [`sig_scan`] — every readable region in
/// `/proc/self/maps` — but collects every occurrence instead of stopping
/// at the first one.
///
/// # Performance
///
/// Can be slow for short patterns in large address spaces. Prefer
/// [`sig_scan`] or [`sig_scan_module`] when only the first match is needed.
pub fn sig_scan_all(sig: &Signature) -> Vec<usize> {
    let mut results = Vec::new();

    if let Ok(regions) = readable_regions() {
        for region in &regions {
            let mut offset = 0;
            while offset + sig.len() <= region.size {
                match scan_region_safe(sig, region.start + offset, region.size - offset) {
                    Some(addr) => {
                        results.push(addr);
                        offset = addr - region.start + 1;
                    }
                    None => break,
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    #[test]
    fn parse_exact_pattern() {
        let sig = Signature::from_str("AA BB CC DD").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(sig.bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(sig.mask_hi(), &[true, true, true, true]);
        assert_eq!(sig.mask_lo(), &[true, true, true, true]);
    }

    #[test]
    fn parse_full_wildcards() {
        let sig = Signature::from_str("AA ?? CC ??").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(sig.bytes(), &[0xAA, 0x00, 0xCC, 0x00]);
        assert_eq!(sig.mask_hi(), &[true, false, true, false]);
        assert_eq!(sig.mask_lo(), &[true, false, true, false]);
    }

    #[test]
    fn parse_nibble_wildcard_high() {
        let sig = Signature::from_str("?A").unwrap();
        assert_eq!(sig.len(), 1);
        assert_eq!(sig.bytes()[0], 0x0A);
        assert_eq!(sig.mask_hi(), &[false]);
        assert_eq!(sig.mask_lo(), &[true]);
    }

    #[test]
    fn parse_nibble_wildcard_low() {
        let sig = Signature::from_str("A?").unwrap();
        assert_eq!(sig.len(), 1);
        assert_eq!(sig.bytes()[0], 0xA0);
        assert_eq!(sig.mask_hi(), &[true]);
        assert_eq!(sig.mask_lo(), &[false]);
    }

    #[test]
    fn parse_mixed_pattern() {
        let sig = Signature::from_str("48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??").unwrap();
        assert_eq!(sig.len(), 12);
    }

    #[test]
    fn parse_empty() {
        let sig = Signature::from_str("").unwrap();
        assert!(sig.is_empty());
    }

    #[test]
    fn parse_invalid_hex() {
        assert!(Signature::from_str("ZZ").is_err());
    }

    #[test]
    fn parse_invalid_length() {
        assert!(Signature::from_str("???").is_err());
        assert!(Signature::from_str("A BB C").is_err()); // odd nibbles
    }

    #[test]
    fn parse_lowercase() {
        let sig = Signature::from_str("aa bb cc").unwrap();
        assert_eq!(sig.bytes(), &[0xAA, 0xBB, 0xCC]);
    }

    // ------------------------------------------------------------------
    // Debug display
    // ------------------------------------------------------------------

    #[test]
    fn debug_format_exact() {
        let sig = Signature::from_str("AA BB").unwrap();
        assert_eq!(format!("{:?}", sig), "Signature(\"AA BB\")");
    }

    #[test]
    fn debug_format_with_wildcards() {
        let sig = Signature::from_str("AA ?? CC").unwrap();
        assert_eq!(format!("{:?}", sig), "Signature(\"AA ?? CC\")");
    }

    #[test]
    fn debug_format_nibble_wildcards() {
        let sig = Signature::from_str("?A B?").unwrap();
        let dbg = format!("{:?}", sig);
        assert!(dbg.contains("?A") && dbg.contains("B?"));
    }

    // ------------------------------------------------------------------
    // Matching
    // ------------------------------------------------------------------

    #[test]
    fn matches_exact() {
        let sig = Signature::from_str("11 22 33 44").unwrap();
        let data: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        assert!(unsafe { sig.matches_at(data.as_ptr()) });
    }

    #[test]
    fn matches_with_wildcard() {
        let sig = Signature::from_str("11 ?? 33 44").unwrap();
        let data: [u8; 4] = [0x11, 0x99, 0x33, 0x44];
        assert!(unsafe { sig.matches_at(data.as_ptr()) });
    }

    #[test]
    fn matches_nibble_wildcard_high() {
        let sig = Signature::from_str("?2 33").unwrap();
        let data: [u8; 2] = [0xA2, 0x33];
        assert!(unsafe { sig.matches_at(data.as_ptr()) });
    }

    #[test]
    fn matches_nibble_wildcard_low() {
        let sig = Signature::from_str("2? 33").unwrap();
        let data: [u8; 2] = [0x2F, 0x33];
        assert!(unsafe { sig.matches_at(data.as_ptr()) });
    }

    #[test]
    fn no_match_exact() {
        let sig = Signature::from_str("11 22 33 44").unwrap();
        let data: [u8; 4] = [0x11, 0x22, 0x33, 0x45];
        assert!(!unsafe { sig.matches_at(data.as_ptr()) });
    }

    #[test]
    fn no_match_nibble_wildcard() {
        let sig = Signature::from_str("?2 33").unwrap();
        let data: [u8; 2] = [0xA3, 0x33]; // low nibble of first byte is 3, not 2
        assert!(!unsafe { sig.matches_at(data.as_ptr()) });
    }

    // ------------------------------------------------------------------
    // Scanning
    // ------------------------------------------------------------------

    #[test]
    fn scan_range_finds_pattern() {
        let sig = Signature::from_str("DE AD BE EF").unwrap();
        let data: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let addr = data.as_ptr() as usize;
        assert_eq!(unsafe { sig_scan_range(&sig, addr, 16) }, Some(addr + 4));
    }

    #[test]
    fn scan_range_not_found() {
        let sig = Signature::from_str("DE AD BE EF").unwrap();
        let data: [u8; 8] = [0x00; 8];
        let addr = data.as_ptr() as usize;
        assert_eq!(unsafe { sig_scan_range(&sig, addr, 8) }, None);
    }

    #[test]
    fn scan_range_too_small() {
        let sig = Signature::from_str("DE AD BE EF").unwrap();
        let data: [u8; 3] = [0; 3];
        let addr = data.as_ptr() as usize;
        assert_eq!(unsafe { sig_scan_range(&sig, addr, 3) }, None);
    }

    #[test]
    fn scan_range_empty_sig() {
        let sig = Signature::from_str("").unwrap();
        let data: [u8; 4] = [0; 4];
        let addr = data.as_ptr() as usize;
        assert_eq!(unsafe { sig_scan_range(&sig, addr, 4) }, None);
    }
}
