use bin_obfuscator::run_obfuscation;
use tracing::{error, info};

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .init();

    let input_path = "C:\\Users\\vasie\\Documents\\GitHub\\bin-obfuscator\\testdata\\test.exe";
    let output_path = "C:\\Users\\vasie\\Documents\\GitHub\\bin-obfuscator\\testdata\\test_obfuscated.exe";

    match run_obfuscation(input_path, output_path) {
        Ok(()) => {
            info!("Done.");
        }
        Err(e) => {
            error!("Error: {}", e);
        }
    }
}