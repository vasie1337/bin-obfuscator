use analyzer::AnalyzerContext;
use common::{Logger, debug, error, info};
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

    // Capture original state before applying any transformations
    for runtime_function in &mut runtime_functions {
        runtime_function.capture_original_state();
    }

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
        
        // Log information about the transformation using original state
        if let Some(original) = runtime_function.get_original() {
            info!(
                "Function {} transformation: original RVA {:#x} -> new RVA {:#x}, original size {} -> new size {}, instructions {} -> {}",
                runtime_function.name,
                original.rva,
                runtime_function.rva,
                original.size,
                runtime_function.size,
                original.instructions.len(),
                runtime_function.instructions.len()
            );
        }

        current_rva += function_bytes.len() as u64;
    }

    // patch jmps from original functions to the new functions
    for runtime_function in &mut runtime_functions {
        let src_rva = runtime_function.get_original_rva();
        let dst_rva = runtime_function.rva;

        let relative_offset = (dst_rva as i64) - ((src_rva + 5) as i64);

        let rel32 = relative_offset as i32;

        let mut jmp_bytes = [0u8; 5];
        jmp_bytes[0] = 0xE9;
        jmp_bytes[1..].copy_from_slice(&rel32.to_le_bytes());

        pe_context.write_data_at_rva(src_rva, &jmp_bytes).unwrap();

        info!(
            "Patched JMP at 0x{:x} to 0x{:x} (rel_offset: 0x{:x})",
            src_rva, dst_rva, rel32
        );
    }

    pe_context.create_executable_section(".vasie", &merged_bytes).unwrap();
    info!("Created .vasie section with {} bytes", merged_bytes.len());

    Ok(pe_context.pe_data)
}
