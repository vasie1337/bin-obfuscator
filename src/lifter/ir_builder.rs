use crate::types::{Function, ControlFlowGraph, BasicBlock};
use iced_x86::{Instruction, FlowControl, OpKind};
use std::collections::HashSet;
use anyhow::Result;
use tracing::debug;

pub struct IrBuilder {
    function: Function,
    cfg: ControlFlowGraph,
    next_block_id: usize,
}

impl IrBuilder {
    pub fn new(function: Function) -> Self {
        Self {
            function,
            cfg: ControlFlowGraph::new(),
            next_block_id: 0,
        }
    }

    pub fn build(&mut self) -> Result<()> {
        if self.function.instructions.is_empty() {
            debug!("Function {} has no instructions", self.function.name);
            return Ok(());
        }

        self.identify_basic_block_leaders()?;
        self.build_basic_blocks()?;
        self.build_control_flow_edges()?;
        self.identify_exit_blocks();

        debug!("Built CFG with {} basic blocks for function {}", 
               self.cfg.blocks.len(), self.function.name);
        Ok(())
    }

    pub fn get_cfg(&self) -> &ControlFlowGraph {
        &self.cfg
    }

    fn identify_basic_block_leaders(&mut self) -> Result<()> {
        let mut leaders = HashSet::new();
        
        if let Some(first_instr) = self.function.instructions.first() {
            leaders.insert(first_instr.ip());
        }

        for (i, instruction) in self.function.instructions.iter().enumerate() {
            let flow_control = instruction.flow_control();
            
            match flow_control {
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    if let Some(target) = self.get_branch_target(instruction) {
                        leaders.insert(target);
                    }
                    
                    if flow_control == FlowControl::ConditionalBranch {
                        if let Some(next_instr) = self.function.instructions.get(i + 1) {
                            leaders.insert(next_instr.ip());
                        }
                    }
                }
                _ => {}
            }
        }

        debug!("Identified {} basic block leaders", leaders.len());
        Ok(())
    }

    fn build_basic_blocks(&mut self) -> Result<()> {
        let mut leaders = HashSet::new();
        
        if let Some(first_instr) = self.function.instructions.first() {
            leaders.insert(first_instr.ip());
        }

        for (i, instruction) in self.function.instructions.iter().enumerate() {
            let flow_control = instruction.flow_control();
            
            match flow_control {
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    if let Some(target) = self.get_branch_target(instruction) {
                        leaders.insert(target);
                    }
                    
                    if flow_control == FlowControl::ConditionalBranch {
                        if let Some(next_instr) = self.function.instructions.get(i + 1) {
                            leaders.insert(next_instr.ip());
                        }
                    }
                }
                _ => {}
            }
        }

        let mut current_block: Option<BasicBlock> = None;
        
        for instruction in &self.function.instructions {
            let addr = instruction.ip();
            
            if leaders.contains(&addr) {
                if let Some(block) = current_block.take() {
                    self.cfg.blocks.insert(block.id, block);
                }
                
                let block_id = self.next_block_id;
                self.next_block_id += 1;
                current_block = Some(BasicBlock::new(block_id, addr));
                
                if self.cfg.entry_block.is_none() {
                    self.cfg.entry_block = Some(block_id);
                }
            }
            
            if let Some(ref mut block) = current_block {
                self.cfg.address_to_block.insert(addr, block.id);
                block.add_instruction(instruction.clone());
            }
        }
        
        if let Some(block) = current_block {
            self.cfg.blocks.insert(block.id, block);
        }

        debug!("Built {} basic blocks", self.cfg.blocks.len());
        Ok(())
    }

    fn build_control_flow_edges(&mut self) -> Result<()> {
        let block_ids: Vec<usize> = self.cfg.blocks.keys().copied().collect();
        
        for block_id in block_ids {
            if let Some(block) = self.cfg.blocks.get(&block_id).cloned() {
                if let Some(last_instr) = block.instructions.last() {
                    let flow_control = last_instr.flow_control();
                    
                    match flow_control {
                        FlowControl::UnconditionalBranch => {
                            if let Some(target) = self.get_branch_target(last_instr) {
                                if let Some(target_block_id) = self.cfg.address_to_block.get(&target) {
                                    self.add_edge(block_id, *target_block_id);
                                }
                            }
                        }
                        FlowControl::ConditionalBranch => {
                            if let Some(target) = self.get_branch_target(last_instr) {
                                if let Some(target_block_id) = self.cfg.address_to_block.get(&target) {
                                    self.add_edge(block_id, *target_block_id);
                                }
                            }
                            
                            let next_addr = last_instr.ip() + last_instr.len() as u64;
                            if let Some(next_block_id) = self.cfg.address_to_block.get(&next_addr) {
                                self.add_edge(block_id, *next_block_id);
                            }
                        }
                        FlowControl::Return => {
                        }
                        _ => {
                            let next_addr = last_instr.ip() + last_instr.len() as u64;
                            if let Some(next_block_id) = self.cfg.address_to_block.get(&next_addr) {
                                self.add_edge(block_id, *next_block_id);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    fn add_edge(&mut self, from: usize, to: usize) {
        if let Some(from_block) = self.cfg.blocks.get_mut(&from) {
            from_block.add_successor(to);
        }
        if let Some(to_block) = self.cfg.blocks.get_mut(&to) {
            to_block.add_predecessor(from);
        }
    }

    fn identify_exit_blocks(&mut self) {
        let mut exit_blocks = Vec::new();
        
        for (block_id, block) in &self.cfg.blocks {
            if block.successors.is_empty() {
                exit_blocks.push(*block_id);
            } else if let Some(last_instr) = block.instructions.last() {
                if last_instr.flow_control() == FlowControl::Return {
                    exit_blocks.push(*block_id);
                }
            }
        }
        
        self.cfg.exit_blocks = exit_blocks;
        debug!("Identified {} exit blocks", self.cfg.exit_blocks.len());
    }

    fn get_branch_target(&self, instruction: &Instruction) -> Option<u64> {
        match instruction.op0_kind() {
            OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16 => {
                Some(instruction.near_branch_target())
            }
            _ => None,
        }
    }
}
