pub mod analysis;
pub mod binary;
pub mod lifter;
pub mod lowerer;
pub mod pipeline;
pub mod types;

use std::path::Path;

pub fn run_obfuscation<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[1/7] Loading {:?}...", input_path.as_ref());
    let pe_file = binary::pe::load_from_disk(input_path.as_ref())?;
        
    println!("[2/7] Analyzing functions and control flow...");
    let mut functions = analysis::function_discovery::analyze_binary(&pe_file)?;

    {
        // Filter out all functions except the main function
        let main_function = functions.iter().find(|f| f.rva == 0x1100).unwrap();
        functions = functions.iter().filter(|f| f.rva == main_function.rva).cloned().collect();
    }

    println!("[3/7] Lifting machine code to IR...");
    let ir = lifter::ir_builder::lift(&pe_file, &functions)?;

    println!("[4/7] Running obfuscation pipeline...");
    let _obfuscated_ir = pipeline::orchestrator::run(ir);

    // TODO: Implement this later
    //println!("[5/7] Lowering IR back to machine code...");
    //let new_code = lowerer::code_gen::lower(&obfuscated_ir)?;

    //println!("[6/7] Creating new section and patching binary...");
    //binary::pe::patch_with_new_code(&mut pe_file, &new_code)?;

    println!("[7/7] Saving new executable to {:?}...", output_path.as_ref());
    binary::pe::save_to_disk(&pe_file, output_path.as_ref())?;

    println!("\nSuccess! Obfuscation complete.");
    Ok(())
}