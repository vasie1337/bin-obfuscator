use analyzer::AnalyzerContext;
use compiler::CompilerContext;
use common::{Logger, error, info};
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;

pub mod analyzer;
pub mod function;
pub mod compiler;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let pe_context = parse_and_validate_pe(binary_data)?;
    info!("PE parsed successfully");

    let pdb_context = parse_and_validate_pdb(pdb_data)?;
    info!("PDB parsed successfully");

    let mut analyzer_context = AnalyzerContext::new(pe_context.clone(), pdb_context);
    let mut runtime_functions = analyzer_context.analyze()
        .map_err(|e| format!("Analysis failed: {}", e))?;

    info!("Analyzed {} runtime functions", runtime_functions.len());

    let mut compiler_context = CompilerContext::new(pe_context);
    compiler_context.compile_functions(&mut runtime_functions)?;

    info!("Compiled {} runtime functions", runtime_functions.len());

    Ok(compiler_context.get_binary_data())
}

fn parse_and_validate_pe(binary_data: &[u8]) -> Result<PEContext, String> {
    let pe_context = PEContext::new(binary_data.to_vec());
    if !pe_context.is_supported() {
        error!("PE is not supported");
        return Err("PE is not supported".to_string());
    }
    Ok(pe_context)
}

fn parse_and_validate_pdb(pdb_data: &[u8]) -> Result<PDBContext, String> {
    let pdb_context = PDBContext::new(pdb_data.to_vec());
    if !pdb_context.is_supported() {
        error!("PDB is not supported");
        return Err("PDB is not supported".to_string());
    }
    Ok(pdb_context)
}
