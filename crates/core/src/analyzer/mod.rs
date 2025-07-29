pub mod functions;

use iced_x86::Instruction;
use parsers::pdb::{PDBContext, PDBFunction};
use parsers::pe::PEContext;

pub struct RuntimeFunction {
    pub pdb_function: PDBFunction,
    pub instructions: Vec<Instruction>,
}

pub struct AnalyzerContext {
    pub pe_context: PEContext,
    pub pdb_context: PDBContext,
}
