pub mod analysis;
pub mod binary;
pub mod lifter;
pub mod lowerer;
pub mod pipeline;
pub mod types;

use std::path::Path;
use tracing::info;

use crate::binary::SectionOperations;

pub fn run_obfuscation<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("[1/7] Loading {:?}", input_path.as_ref());
    let mut pe_file: binary::PeFile = binary::pe::load_from_disk(input_path.as_ref())?;

    info!("[2/7] Analyzing functions and control flow...");
    let mut functions = analysis::function_discovery::analyze_binary(&pe_file)?;

    {
        // Filter out all functions except the main function
        let main_function = functions.iter().find(|f| f.rva == 0x1100).unwrap();
        functions = functions.iter().filter(|f| f.rva == main_function.rva).cloned().collect();
    }

    info!("[3/7] Lifting machine code to IR...");
    let ir = lifter::ir_builder::lift(&pe_file, &functions)?;

    info!("[4/7] Running obfuscation pipeline...");
    let obfuscated_ir = pipeline::orchestrator::run(pe_file.get_bitness()?, ir);

    let new_section_rva = pe_file.get_next_section_rva()?;
    info!("New section RVA: 0x{:x}", new_section_rva);

    info!("[5/7] Lowering IR back to machine code...");
    let new_code = lowerer::code_gen::lower(&obfuscated_ir, new_section_rva)?;

    info!("[6/7] Creating new section and patching binary...");
    binary::pe::patch_with_new_code(&mut pe_file, &new_code)?;

    info!("[7/7] Saving new executable to {:?}...", output_path.as_ref());
    binary::pe::save_to_disk(&pe_file, output_path.as_ref())?;

    info!("Success! Obfuscation complete.");
    Ok(())
}