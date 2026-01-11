mod analysis;
mod types;

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

    println!("\nFirst 10 functions:");
    for func in functions.iter().take(10) {
        println!("  {}", func);
    }

    Ok(vec![])
}

