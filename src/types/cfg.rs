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

    pub fn relocate_addresses(&mut self, new_section_rva: u64) {
        let original_entry_rva = self.get_entry_rva().unwrap_or(0);
        let offset = new_section_rva as i64 - original_entry_rva as i64;
        
        let old_mappings: Vec<_> = self.address_to_block.drain().collect();
        for (old_addr, block_id) in old_mappings {
            let new_addr = (old_addr as i64 + offset) as u64;
            self.address_to_block.insert(new_addr, block_id);
        }
        
        for block in self.blocks.values_mut() {
            block.start_address = (block.start_address as i64 + offset) as u64;
            block.end_address = (block.end_address as i64 + offset) as u64;
        }
    }
}

pub fn relocate_cfg_addresses(cfgs: &mut [ControlFlowGraph], new_section_rva: u64) {
    for cfg in cfgs {
        cfg.relocate_addresses(new_section_rva);
    }
}