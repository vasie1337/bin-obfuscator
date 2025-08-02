use analyzer::AnalyzerContext;
use common::{Logger, info};
use function::RuntimeFunction;
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;
use compiler::CompilerContext;
use obfuscator::Obfuscator;
use std::cell::RefCell;
use std::rc::Rc;

pub mod analyzer;
pub mod function;
pub mod passes;
pub mod compiler;
pub mod obfuscator;

pub struct CoreContext {
    pub pe_context: Rc<RefCell<PEContext>>,
    pub pdb_context: Rc<RefCell<PDBContext>>,
}

impl CoreContext {
    pub fn new(pe_context: Rc<RefCell<PEContext>>, pdb_context: Rc<RefCell<PDBContext>>) -> Self {
        Self { pe_context, pdb_context }
    }
}

pub fn run(binary_data: &[u8], pdb_data: &[u8]) -> Result<Vec<u8>, String> {
    Logger::ensure_init();

    let pe_context = parse_and_validate_pe(binary_data)?;
    let pdb_context = parse_and_validate_pdb(pdb_data)?;
    let core_context = CoreContext::new(pe_context, pdb_context);
    info!("Parsed PE and PDB");

    let mut runtime_functions = analyze_binary(&core_context)?;
    info!("Analyzed {} runtime functions", runtime_functions.len());

    obfuscate_binary(&mut runtime_functions)?;
    info!("Obfuscated {} runtime functions", runtime_functions.len());

    let binary_data = compile_binary(&core_context, &mut runtime_functions)?;
    info!("Compiled {} runtime functions", runtime_functions.len());

    Ok(binary_data)
}

fn parse_and_validate_pe(binary_data: &[u8]) -> Result<Rc<RefCell<PEContext>>, String> {
    let pe_context = PEContext::new(binary_data.to_vec());
    if !pe_context.is_supported() {
        return Err("PE is not supported".to_string());
    }
    Ok(Rc::new(RefCell::new(pe_context)))
}

fn parse_and_validate_pdb(pdb_data: &[u8]) -> Result<Rc<RefCell<PDBContext>>, String> {
    let pdb_context = PDBContext::new(pdb_data.to_vec());
    if !pdb_context.is_supported() {
        return Err("PDB is not supported".to_string());
    }
    Ok(Rc::new(RefCell::new(pdb_context)))
}

fn analyze_binary(core_context: &CoreContext) -> Result<Vec<RuntimeFunction>, String> {
    let analyzer_context = AnalyzerContext::new(core_context);
    let runtime_functions = analyzer_context.analyze()?;
    Ok(runtime_functions)
}

fn obfuscate_binary(functions: &mut Vec<RuntimeFunction>) -> Result<(), String> {
    let obfuscator = Obfuscator::new();
    obfuscator.obfuscate(functions)?;
    Ok(())
}

fn compile_binary(core_context: &CoreContext, functions: &mut Vec<RuntimeFunction>) -> Result<Vec<u8>, String> {
    let mut compiler_context = CompilerContext::new(core_context.pe_context.clone());
    compiler_context.compile_functions(functions)?;
    Ok(compiler_context.get_binary_data())
}