use analyzer::AnalyzerContext;
use common::{Logger, error, info};
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;
use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};

pub mod analyzer;
pub mod function;

pub fn obfuscate_binary(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let mut pe_context = PEContext::new(binary_data.to_vec());
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

    let mut analyzer_context = AnalyzerContext::new(pe_context.clone(), pdb_context);
    let runtime_functions = analyzer_context.analyze().unwrap();

    let all_instructions = runtime_functions.iter().flat_map(|f| f.instructions.iter()).copied().collect::<Vec<_>>();
    
    let rva = pe_context.get_next_section_rva().unwrap();

    let block = InstructionBlock::new(&all_instructions, rva);
    let bytes = match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
        Ok(bytes) => bytes.code_buffer,
        Err(e) => return Err(e.to_string()),
    };

    pe_context.create_executable_section(".vasie", &bytes).unwrap();

    Ok(pe_context.pe_data)
}
