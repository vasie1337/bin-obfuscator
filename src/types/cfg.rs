use std::collections::HashMap;
use crate::types::BasicBlock;

#[derive(Debug)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<usize, BasicBlock>,
    pub address_to_block: HashMap<u64, usize>,
    pub entry_block: Option<usize>,
    pub exit_blocks: Vec<usize>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            address_to_block: HashMap::new(),
            entry_block: None,
            exit_blocks: Vec::new(),
        }
    }
}
