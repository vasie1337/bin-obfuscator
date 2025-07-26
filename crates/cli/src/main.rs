use common::{Logger, info};

fn main() {
    Logger::init().unwrap();
    info!("Starting the binary obfuscator");
}