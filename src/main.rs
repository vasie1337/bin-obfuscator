mod binary;
mod analysis;
mod types;

use binary::PeFile;
use crate::analysis::FunctionDiscovery;
use tracing::{error, info};

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

    let mut function_discovery = FunctionDiscovery::new(pe_file).unwrap();
    
    let functions = function_discovery.run().unwrap();
    for function in functions {
        info!("Function at 0x{:x}: {:?}", function.start_rva, function);
    }
}