pub mod loader;

use crate::types::Function;
use std::cell::RefCell;

pub struct PDBContext {
    pdb_data: Vec<u8>,
    functions: RefCell<Option<Vec<Function>>>,
}
