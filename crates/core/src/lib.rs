use analyzer::AnalyzerContext;
use common::{Logger, debug, info, warn};
use compiler::CompilerContext;
use function::ObfuscatorFunction;
use instant::Instant;
use obfuscator::Obfuscator;
use pdb::PDBContext;
use pe::PEContext;
use std::cell::RefCell;
use std::rc::Rc;

pub mod analyzer;
pub mod compiler;
pub mod function;
pub mod obfuscator;
pub mod passes;
pub mod pdb;
pub mod pe;

pub struct CoreContext {
    pub pe_context: Rc<RefCell<PEContext>>,
    pub pdb_context: Rc<RefCell<PDBContext>>,
}

impl CoreContext {
    pub fn new(pe_context: Rc<RefCell<PEContext>>, pdb_context: Rc<RefCell<PDBContext>>) -> Self {
        Self {
            pe_context,
            pdb_context,
        }
    }
}

pub fn run(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let start_time = Instant::now();
    info!("Starting binary obfuscation process");
    debug!(
        "PE binary size: {} bytes, PDB size: {} bytes",
        binary_data.len(),
        pdb_data.len()
    );

    let pe_context = parse_and_validate_pe(binary_data)?;
    let pdb_context = parse_and_validate_pdb(pdb_data)?;

    let core_context = CoreContext::new(pe_context, pdb_context);

    let mut obfuscator_functions = analyze_binary(&core_context)?;

    obfuscate_binary(&mut obfuscator_functions)?;

    let binary_data = compile_binary(&core_context, &mut obfuscator_functions)?;

    let elapsed = start_time.elapsed();
    info!(
        "Successfully completed obfuscation of {} functions in {:.2}ms",
        obfuscator_functions.len(),
        elapsed.as_secs_f64() * 1000.0,
    );

    Ok(binary_data)
}

fn parse_and_validate_pe(binary_data: &[u8]) -> Result<Rc<RefCell<PEContext>>, String> {
    debug!("Parsing and validating PE binary");
    let pe_context = PEContext::new(binary_data.to_vec());
    if !pe_context.is_supported() {
        warn!("PE binary is not supported");
        return Err("PE is not supported".to_string());
    }
    debug!("PE binary successfully parsed and validated");
    Ok(Rc::new(RefCell::new(pe_context)))
}

fn parse_and_validate_pdb(pdb_data: &[u8]) -> Result<Rc<RefCell<PDBContext>>, String> {
    debug!("Parsing and validating PDB file");
    let pdb_context = PDBContext::new(pdb_data.to_vec());
    if !pdb_context.is_supported() {
        warn!("PDB file is not supported");
        return Err("PDB is not supported".to_string());
    }
    debug!("PDB file successfully parsed and validated");
    Ok(Rc::new(RefCell::new(pdb_context)))
}

fn analyze_binary(core_context: &CoreContext) -> Result<Vec<ObfuscatorFunction>, String> {
    info!("Starting binary analysis phase");
    let analyzer_context = AnalyzerContext::new(core_context);
    let obfuscator_functions = analyzer_context.analyze()?;
    info!(
        "Binary analysis completed, found {} functions",
        obfuscator_functions.len()
    );
    Ok(obfuscator_functions)
}

fn obfuscate_binary(functions: &mut Vec<ObfuscatorFunction>) -> Result<(), String> {
    info!(
        "Starting obfuscation phase for {} functions",
        functions.len()
    );
    let obfuscator = Obfuscator::new();
    obfuscator.obfuscate(functions)?;
    info!("Obfuscation phase completed successfully");
    Ok(())
}

fn compile_binary(
    core_context: &CoreContext,
    functions: &mut Vec<ObfuscatorFunction>,
) -> Result<Vec<u8>, String> {
    info!(
        "Starting compilation phase for {} functions",
        functions.len()
    );
    let mut compiler_context = CompilerContext::new(core_context.pe_context.clone());
    compiler_context.compile_functions(functions)?;
    let binary_data = compiler_context.get_binary_data();
    info!(
        "Compilation phase completed, generated {} bytes",
        binary_data.len()
    );
    Ok(binary_data)
}
