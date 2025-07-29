pub mod loader;
pub mod patcher;
pub mod sections;
pub mod finalizer;

use goblin::pe::PE;

pub struct PEContext {
    pub pe_data: Vec<u8>,
    pub pe: PE<'static>,
}
