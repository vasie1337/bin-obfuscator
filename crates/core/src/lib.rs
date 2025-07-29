use common::{Logger, error, info};
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let pe_context = PEContext::new(binary_data.to_vec());
    match pe_context.parse() {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to parse PE: {e}");
            return Err(e);
        }
    }

    info!("PE parsed successfully");

    let pdb_context = PDBContext::new(pdb_data.to_vec());
    match pdb_context.parse() {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to parse PDB: {e}");
            return Err(e);
        }
    }

    info!("PDB parsed successfully");

    pe_context.finalize();

    Ok(binary_data.to_vec())
}
