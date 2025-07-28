pub mod loader;
pub mod patcher;
pub mod sections;
pub mod finalizer;

use goblin::pe::PE;
use std::cell::RefCell;

pub struct PEContext {
    pub pe_data: Vec<u8>,
    pub pe: RefCell<Option<PE<'static>>>,
}
