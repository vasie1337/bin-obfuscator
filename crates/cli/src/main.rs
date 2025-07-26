use common::{Logger, info};

fn main() {
    Logger::ensure_init();
    info!("Starting the binary obfuscator");
    core::obfuscate_binary("C:\\Windows\\System32\\notepad.exe");
}