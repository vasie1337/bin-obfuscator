pub mod analysis;
pub mod binary;
pub mod lifter;
pub mod lowerer;
pub mod pipeline;
pub mod types;

use std::path::Path;
use tracing::info;

use crate::binary::SectionOperations;
use anyhow::Result;

pub fn run_obfuscation<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("[1/8] Loading {:?}", input_path.as_ref());
    let mut pe_file: binary::PeFile = binary::pe::load_from_disk(input_path.as_ref())?;

    info!("[2/8] Analyzing functions and control flow...");
    let mut functions = analysis::function_discovery::analyze_binary(&pe_file)?;

    { // WILL BE REMOVED
        let main_function = functions.iter().find(|f| f.rva == 0x1100).unwrap();
        functions = functions.iter().filter(|f| f.rva == main_function.rva).cloned().collect();
    } // WILL BE REMOVED

    info!("[3/8] Lifting machine code to IR...");
    let ir = lifter::ir_builder::lift(&pe_file, &functions)?;

    info!("[4/8] Running obfuscation pipeline...");
    let mut obfuscated_ir = pipeline::orchestrator::run(pe_file.get_bitness()?, &ir);

    info!("[5/8] Relocating obfuscated code to new section...");
    let new_section_rva = pe_file.get_next_section_rva()?;
    types::cfg::relocate_cfg_addresses(&mut obfuscated_ir, new_section_rva);

    info!("[6/8] Fixing function calls...");
    binary::pe::fix_calls(&mut pe_file, &ir, &obfuscated_ir)?;

    info!("[7/8] Lowering IR back to machine code...");
    let new_code = lowerer::code_gen::lower(&obfuscated_ir, new_section_rva)?;

    info!("[8/9] Creating new section and patching binary...");
    binary::pe::patch_with_new_code(&mut pe_file, &new_code)?;

    info!("[9/9] Saving new executable to {:?}...", output_path.as_ref());
    binary::pe::save_to_disk(&pe_file, output_path.as_ref())?;
    
    Ok(())
}