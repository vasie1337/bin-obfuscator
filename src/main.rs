mod binary;
mod analysis;
mod types;

use binary::PeFile;
use crate::analysis::FunctionDiscovery;
use tracing::{error, info};
use iced_x86::{Formatter, NasmFormatter};

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .init();

    let mut pe_file = PeFile::new();
    if let Err(e) = pe_file.load("C:\\Users\\vasie\\Documents\\GitHub\\bin-obfuscator\\testdata\\test.exe") {
        error!("Failed to load PE file: {}", e);
        return;
    }
    info!("PE file loaded");

    let mut formatter = NasmFormatter::new();
    let mut output = String::new();

    let mut function_discovery = FunctionDiscovery::new(pe_file).unwrap();
    let functions = function_discovery.run().unwrap();
    info!("Discovered {} functions", functions.len());

    let main_function = functions.iter().find(|f| f.start_rva == 0x1100).unwrap();
    info!("\n=== {} ===", main_function.name);
    info!("Address: 0x{:x} - 0x{:x} (Size: {} bytes)", 
          main_function.start_rva, 
          main_function.start_rva + main_function.size, 
          main_function.size);
    info!("Instructions: {}", main_function.instructions.len());

    for (_, instruction) in main_function.instructions.iter().enumerate() {
        output.clear();
        formatter.format(&instruction, &mut output);
        info!("  0x{:08x}: {}", instruction.ip(), output);
    }
}