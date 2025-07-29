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
    let runtime_functions = analyzer_context.analyze().unwrap();

    //for runtime_function in runtime_functions.iter() {
    //    info!("Function: {:?}", runtime_function.pdb_function.name);
    //    for instruction in runtime_function.instructions.iter() {
    //        info!("Instruction: {:?}", instruction.to_string());
    //    }
    //}

    // Print some stats
    info!("Runtime functions: {}", runtime_functions.len());
    info!(
        "Total instructions: {}",
        runtime_functions
            .iter()
            .map(|f| f.instructions.len())
            .sum::<usize>()
    );
    info!(
        "Total bytes: {}",
        runtime_functions
            .iter()
            .map(|f| f.instructions.iter().map(|i| i.len()).sum::<usize>())
            .sum::<usize>()
    );

    // Print the first 10 instructions of the first function
    info!(
        "First 10 instructions of the first function: {:?}",
        runtime_functions[0].instructions[0..10]
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<String>>()
    );

    Ok(binary_data.to_vec())
}
