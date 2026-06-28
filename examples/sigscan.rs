//! # Yuyu — Signature Scan Example
//!
//! Demonstrates AOB (Array of Bytes) pattern searching across readable memory
//! regions. This is useful for locating functions or data by their binary
//! fingerprint when you don't have symbol information.
//!
//! ```sh
//! cargo run --example sigscan
//! ```

use std::str::FromStr;
use yuyu::memory::sigscan::{Signature, sig_scan, sig_scan_module, sig_scan_range};

fn main() {
    println!("=== Yuyu Signature Scan Example ===\n");

    // ---- 1. Scan a known buffer (sig_scan_range) ----
    println!("1. sig_scan_range — scan a known buffer:");

    // Create a buffer with a unique 8-byte fingerprint
    let marker: [u8; 8] = [0x13, 0x37, 0x42, 0x42, 0x99, 0x88, 0x77, 0x66];
    let pattern = format!(
        "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
        marker[0], marker[1], marker[2], marker[3], marker[4], marker[5], marker[6], marker[7],
    );
    println!("   Pattern : {}", pattern);
    let sig = Signature::from_str(&pattern).expect("invalid pattern");
    println!("   Debug   : {:?}", sig);

    // Search in a 64-byte window around the buffer
    let buf_addr = marker.as_ptr() as usize;
    match unsafe { sig_scan_range(&sig, buf_addr.saturating_sub(32), 64) } {
        Some(addr) => {
            println!("   Found at: 0x{:X}", addr);
            assert_eq!(addr, buf_addr, "should match buffer start exactly");
            println!("   ✓ Address matches buffer start");
        }
        None => println!("   Not found (unexpected!)"),
    }

    // ---- 2. Full scan with wildcards ----
    println!("\n2. sig_scan — wildcards, all readable regions:");

    // Wildcard the middle 4 bytes of the marker
    let wildcard_pat = "13 37 ?? ?? 99 88 77 66";
    println!("   Pattern: {}", wildcard_pat);
    let sig = Signature::from_str(wildcard_pat).unwrap();

    match sig_scan(&sig) {
        Some(addr) => println!("   Found at: 0x{:X}", addr),
        None => println!("   Not found"),
    }

    // ---- 3. Module-scoped scan ----
    println!("\n3. sig_scan_module — restrict to a module:");

    let sig = Signature::from_str(&pattern).unwrap();
    match sig_scan_module(&sig, "sigscan") {
        Some(addr) => println!("   Found at: 0x{:X} (in sigscan example mappings)", addr),
        None => println!("   Not found in this module"),
    }

    // Try a module that shouldn't have it
    match sig_scan_module(&sig, "nonexistent_lib") {
        Some(addr) => println!("   Unexpectedly found at 0x{:X}", addr),
        None => println!("   Correctly not found in 'nonexistent_lib'"),
    }

    // ---- 4. Find all occurrences (in a safe buffer) ----
    println!("\n4. sig_scan_all — all occurrences in a buffer:");

    // Build a buffer with two copies of our marker
    let mut haystack = [0u8; 64];
    haystack[10..18].copy_from_slice(&marker);
    haystack[40..48].copy_from_slice(&marker);

    let sig = Signature::from_str(&pattern).unwrap();
    let haystack_addr = haystack.as_ptr() as usize;

    let results: Vec<usize> = {
        let mut addrs = Vec::new();
        let mut offset = 0;
        while offset + sig.len() <= haystack.len() {
            if unsafe { sig.matches_at(haystack_addr.wrapping_add(offset) as *const u8) } {
                addrs.push(haystack_addr + offset);
            }
            offset += 1;
        }
        addrs
    };
    println!("   Occurrences: {}", results.len());
    for (i, addr) in results.iter().enumerate() {
        let off = addr - haystack_addr;
        println!("     [{}] offset {} (0x{:X})", i, off, addr);
    }
    assert_eq!(results.len(), 2, "should find both copies");
    println!("   ✓ Found both copies");

    // ---- 5. Nibble-level wildcards ----
    println!(
        "\n5. Nibble-wildcard matching — '{:?}':",
        Signature::from_str("?3").unwrap()
    );

    let sig = Signature::from_str("?3").unwrap();
    let test_bytes: [u8; 4] = [0x13, 0x37, 0x42, 0x99];
    for &b in &test_bytes {
        let matched = unsafe { sig.matches_at(&b as *const u8) };
        println!(
            "   matches_at(0x{:02X}) = {}  (low nibble {} 0x3)",
            b,
            matched,
            if b & 0x0F == 0x3 { "==" } else { "!=" }
        );
    }

    // ---- 6. AArch64 function prologue scan ----
    println!("\n6. sig_scan_module — find AArch64 function prologues:");

    // Many AArch64 functions start with:
    //   STP x29, x30, [sp, #-imm]!  →  FD 7B BF A9  (imm=0)
    //   MOV x29, sp                  →  FD 03 00 91
    // The STP immediate varies per function, so we wildcard it.
    let prologue = "FD 7B ?? A9 FD 03 00 91";
    println!("   Pattern: {}", prologue);
    let sig = Signature::from_str(prologue).unwrap();

    match sig_scan_module(&sig, "sigscan") {
        Some(addr) => println!("   Found function entry at 0x{:X}", addr),
        None => println!("   No matching prologue in this module"),
    }

    // ---- 7. CLI-style convenience ----
    println!("\n7. Parse-and-scan in one line:");

    let addr = Signature::from_str("13 37 42 42")
        .ok()
        .and_then(|s| sig_scan(&s));
    println!(
        "   sig_scan(\"13 37 42 42\") → {}",
        match addr {
            Some(a) => format!("0x{:X}", a),
            None => "None".to_string(),
        }
    );

    println!("\n=== All scans completed! ===");
}
