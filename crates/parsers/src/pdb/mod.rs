pub mod parser;

use std::cell::RefCell;

#[derive(Clone)]
#[allow(dead_code)]
pub struct PDBFunction {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

pub struct PDBContext {
    pdb_data: Vec<u8>,
    functions: RefCell<Option<Vec<PDBFunction>>>,
}
