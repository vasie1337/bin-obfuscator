pub mod parser;

use std::fmt::{Debug, Formatter};

pub enum PEType {
    DLL,
    EXE,
    SYS,
    UNKNOWN,
}

impl Debug for PEType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PEType::DLL => write!(f, "DLL"),
            PEType::EXE => write!(f, "EXE"),
            PEType::SYS => write!(f, "SYS"),
            PEType::UNKNOWN => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Clone)]
pub struct PEContext {
    pub pe_data: Vec<u8>,
}
