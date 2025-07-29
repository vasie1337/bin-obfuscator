use analyzer::AnalyzerContext;
use common::{Logger, error, info};
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;

pub mod analyzer;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let pe_context = PEContext::new(binary_data.to_vec());
    if !pe_context.is_supported() {
        error!("PE is not supported");
        return Err("PE is not supported".to_string());
    }

    info!("PE parsed successfully");

    let pdb_context = PDBContext::new(pdb_data.to_vec());
    if !pdb_context.is_supported() {
        error!("PDB is not supported");
        return Err("PDB is not supported".to_string());
    }

    info!("PDB parsed successfully");

    let mut analyzer_context = AnalyzerContext::new(pe_context, pdb_context);
    analyzer_context.analyze().unwrap();

    Ok(binary_data.to_vec())
}
