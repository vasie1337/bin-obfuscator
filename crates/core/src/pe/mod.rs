pub mod loader;
pub mod patcher;
pub mod sections;
pub mod finalizer;

use goblin::pe::PE;
use std::cell::RefCell;
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

pub struct PEContext {
    pub pe_data: Vec<u8>,
    pub pe: RefCell<Option<PE<'static>>>,
}
