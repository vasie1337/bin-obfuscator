mod analysis;
mod types;

pub use analysis::discover_functions;
pub use types::{FunctionInfo, FunctionSource};

use pelite::pe::PeFile;
use std::collections::HashMap;

pub fn obfuscate(pe_binary: &[u8]) -> Result<Vec<u8>, String> {
    let file = PeFile::from_bytes(pe_binary).map_err(|e| e.to_string())?;

    let functions: Vec<FunctionInfo> = analysis::discover_functions(&file)?;

    println!("Found {} unique functions", functions.len());

    let stats = functions.iter().fold(HashMap::new(), |mut stats, func| {
        *stats.entry(func.source.clone()).or_insert(0) += 1;
        stats
    });
    println!("Statistics: {:?}", stats);

    // Validate all functions have sizes
    let functions_without_size = functions.iter().filter(|f| f.size.is_none()).count();
    if functions_without_size > 0 {
        return Err(format!(
            "FATAL: {} functions don't have size information",
            functions_without_size
        ));
    }
    println!("✓ All {} functions have size information", functions.len());

    // Check for overlaps (critical validation for obfuscator)
    for i in 0..functions.len().saturating_sub(1) {
        if let (Some(end1), start2) = (functions[i].end_rva, functions[i + 1].start_rva) {
            if end1 > start2 {
                return Err(format!(
                    "FATAL: Function overlap detected!\n  Function at 0x{:08X} ends at 0x{:08X}\n  Next function starts at 0x{:08X}",
                    functions[i].start_rva, end1, start2
                ));
            }
        }
    }
    println!("✓ No overlapping functions detected");

    println!("\nLargest 10 functions:");

    // remove functions that are found in the exception handler
    let functions: Vec<FunctionInfo> = functions
        .clone()
        .into_iter()
        .filter(|f| f.source != FunctionSource::ExceptionHandler)
        .collect();

    // Sort functions by size
    let mut sorted_functions = functions.clone();
    sorted_functions.sort_by(|a, b| b.size.cmp(&a.size));

    // Display top 10 largest functions
    for func in sorted_functions.iter().take(10) {
        println!(
            "  0x{:08X} - Size: {} bytes - Source: {:?}",
            func.start_rva,
            func.size.unwrap_or(0),
            func.source
        );
    }

    Ok(vec![])
}
