mod pe;
mod pdb;
mod types;

use common::{Logger};
use crate::pe::PEContext;
use crate::pdb::PDBContext;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let pe_context = PEContext::new(binary_data.to_vec());
    pe_context.load().unwrap();

    let pdb_context = PDBContext::new(pdb_data.to_vec());
    pdb_context.load().unwrap();

    let functions = pdb_context.get_functions().unwrap();
    for function in functions {
        println!("Function: {} - RVA: {} - Size: {}", function.name, function.rva, function.size);
    }


    // TODO: Implement obfuscation

    pe_context.finalize();

    Ok(binary_data.to_vec())
}