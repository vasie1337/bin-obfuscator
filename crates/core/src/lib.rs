mod pe;
mod pdb;
mod types;

use common::{debug, error, Logger};
use crate::pe::PEContext;
use crate::pdb::PDBContext;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let pe_context = PEContext::new(binary_data.to_vec());
    match pe_context.load() {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to load PE: {}", e);
            return Err(e);
        }
    }

    let pdb_context = PDBContext::new(pdb_data.to_vec());
    match pdb_context.load() {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to load PDB: {}", e);
            return Err(e);
        }
    }

    let functions = pdb_context.get_functions().unwrap();
    for function in functions {
        debug!("Function: {} - RVA: {} - Size: {}", function.name, function.rva, function.size);
    }

    // TODO: Implement obfuscation

    pe_context.finalize();

    Ok(binary_data.to_vec())
}