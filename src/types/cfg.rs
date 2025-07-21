use std::collections::HashMap;
use crate::types::BasicBlock;

#[derive(Debug, Clone)]
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

    pub fn get_entry_rva(&self) -> Option<u64> {
        self.entry_block
            .and_then(|entry_id| self.blocks.get(&entry_id))
            .map(|entry_block| entry_block.start_address)
    }
}
