pub mod functions;

use parsers::pdb::PDBFunction;
use iced_x86::Instruction;

pub struct Function {
    pub pdb_function: PDBFunction,
    pub instructions: Vec<Instruction>,
}

pub struct AnalyzerContext {
    pub functions: Vec<Function>,
}
