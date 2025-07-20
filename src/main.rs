mod binary;
use binary::PeFile;

use crate::binary::SectionOperations;
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
    if let Err(e) = pe_file.load("C:\\Windows\\System32\\calc.exe") {
        error!("Failed to load PE file: {}", e);
        return;
    }
    info!("PE file loaded");

    let sections = pe_file.get_code_sections().unwrap();
    info!("Sections: {:?}", sections);
}