pub mod parser;
pub mod sections;

pub enum PEType {
    DLL,
    EXE,
    SYS,
}

#[derive(Clone)]
pub struct PEContext {
    pub pe_data: Vec<u8>,
}
