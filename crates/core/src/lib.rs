use common::{info, Logger};
use goblin::Object;

fn is_pe_file(pe_data: &[u8]) -> bool {
    let buffer = pe_data.to_vec();
    match Object::parse(&buffer) {
        Ok(Object::PE(_pe)) => {
            true
        },
        _ => {
            false
        }
    }
}

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    if !is_pe_file(binary_data) {
        return Err("Binary data is not a valid PE object".to_string());
    }

    if binary_data.len() == 0 {
        return Err("Binary data is empty".to_string());
    }

    if pdb_data.len() == 0 {
        return Err("PDB data is empty".to_string());
    }

    let size_mb = binary_data.len() as f64 / 1024.0 / 1024.0;
    info!("Obfuscating {} mb binary", size_mb);
    
    let binary_data = binary_data.to_vec();
    let _pdb_data = pdb_data.to_vec();

    // TODO: Implement obfuscation

    Ok(binary_data)
}