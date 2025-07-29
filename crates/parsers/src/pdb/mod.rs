pub mod parser;

#[derive(Clone)]
#[allow(dead_code)]
pub struct PDBFunction {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone)]
pub struct PDBContext {
    pdb_data: Vec<u8>,
}
