use analyzer::AnalyzerContext;
use common::{Logger, error, info};
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;
use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};

pub mod analyzer;
pub mod function;
pub mod compiler;
pub mod passes;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    // TODO: Add error handling
    let mut pe_context = PEContext::new(binary_data.to_vec());
    if !pe_context.is_supported() {
        error!("PE is not supported");
        return Err("PE is not supported".to_string());
    }

    info!("PE parsed successfully");

    // TODO: Add error handling
    let pdb_context = PDBContext::new(pdb_data.to_vec());
    if !pdb_context.is_supported() {
        error!("PDB is not supported");
        return Err("PDB is not supported".to_string());
    }

    info!("PDB parsed successfully");

    let pass_manager = passes::PassManager::default();

    let mut analyzer_context = AnalyzerContext::new(pe_context.clone(), pdb_context);
    let mut runtime_functions = analyzer_context.analyze().unwrap();

    let section_base_rva = pe_context.get_next_section_rva().unwrap();

    let mut current_rva = section_base_rva;
    let mut merged_bytes = Vec::new();

    for runtime_function in &mut runtime_functions {
        let transformed_instructions = pass_manager.run_passes(runtime_function.instructions.clone());
        runtime_function.instructions = transformed_instructions;

        let function_bytes = runtime_function.encode(current_rva).unwrap();
        merged_bytes.extend_from_slice(&function_bytes);

        runtime_function.update_rva(current_rva as u32);
        runtime_function.update_size(function_bytes.len() as u32);

        info!("Encoded function {} with {} bytes at RVA {:#x}", runtime_function.name, function_bytes.len(), current_rva);

        current_rva += function_bytes.len() as u64;
    }

    pe_context.create_executable_section(".vasie", &merged_bytes).unwrap();
    info!("Created .vasie section with {} bytes", merged_bytes.len());

    Ok(pe_context.pe_data)
}
