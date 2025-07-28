mod pe;
mod pdb;
mod types;

use common::{Logger};
use crate::pe::PEContext;
use crate::pdb::PDBContext;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let binary_data = binary_data.to_vec();
    let pdb_data = pdb_data.to_vec();

    let pe_context = PEContext::load(&binary_data).unwrap();
    let pdb_context = PDBContext::new(pdb_data);
    
    pe_context.loop_imports();
    pe_context.finalize();

    let functions = pdb_context.get_functions().unwrap();
    for function in functions {
        println!("Function: {} - RVA: {} - Size: {}", function.name, function.rva, function.size);
    }


    // TODO: Implement obfuscation

    Ok(binary_data)
}