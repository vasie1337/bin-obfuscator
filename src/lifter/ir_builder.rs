use crate::types::{Function, ControlFlowGraph, BasicBlock};
use iced_x86::{Instruction, FlowControl, OpKind};
use std::collections::HashSet;
use anyhow::Result;
use tracing::{info, debug, warn, error};

pub struct IrBuilder {
    function: Function,
    cfg: ControlFlowGraph,
    next_block_id: usize,
}

impl IrBuilder {
    pub fn new(function: Function) -> Self {
        info!("Creating IR builder for function: {} (0x{:x})", function.name, function.rva);
        debug!("Function has {} instructions", function.instructions.len());
        Self {
            function,
            cfg: ControlFlowGraph::new(),
            next_block_id: 0,
        }
    }

    pub fn build(&mut self) -> Result<()> {
        info!("Starting IR build process for function: {}", self.function.name);
        
        if self.function.instructions.is_empty() {
            warn!("Function {} has no instructions, skipping IR build", self.function.name);
            return Ok(());
        }

        debug!("Phase 1: Identifying basic block leaders");
        self.identify_basic_block_leaders()?;
        
        debug!("Phase 2: Building basic blocks");
        self.build_basic_blocks()?;
        
        debug!("Phase 3: Building control flow edges");
        self.build_control_flow_edges()?;
        
        debug!("Phase 4: Identifying exit blocks");
        self.identify_exit_blocks();

        info!("Successfully built CFG with {} basic blocks for function {}", 
               self.cfg.blocks.len(), self.function.name);
        
        if let Some(entry_block) = self.cfg.entry_block {
            debug!("Entry block: {}", entry_block);
        }
        debug!("Exit blocks: {:?}", self.cfg.exit_blocks);
        
        Ok(())
    }

    pub fn get_cfg(&self) -> &ControlFlowGraph {
        &self.cfg
    }

    pub fn into_cfg(self) -> ControlFlowGraph {
        self.cfg
    }

    fn identify_basic_block_leaders(&mut self) -> Result<()> {
        debug!("Analyzing {} instructions to find basic block leaders", self.function.instructions.len());
        let mut leaders = HashSet::new();
        
        if let Some(first_instr) = self.function.instructions.first() {
            leaders.insert(first_instr.ip());
            debug!("Added function entry point as leader: 0x{:x}", first_instr.ip());
        }

        let mut branch_count = 0;
        let mut conditional_branch_count = 0;

        for (i, instruction) in self.function.instructions.iter().enumerate() {
            let flow_control = instruction.flow_control();
            
            match flow_control {
                FlowControl::UnconditionalBranch => {
                    branch_count += 1;
                    if let Some(target) = self.get_branch_target(instruction) {
                        leaders.insert(target);
                        debug!("Found unconditional branch from 0x{:x} to 0x{:x}", instruction.ip(), target);
                    } else {
                        debug!("Unconditional branch at 0x{:x} with no direct target (indirect)", instruction.ip());
                    }
                }
                FlowControl::ConditionalBranch => {
                    conditional_branch_count += 1;
                    if let Some(target) = self.get_branch_target(instruction) {
                        leaders.insert(target);
                        debug!("Found conditional branch from 0x{:x} to 0x{:x}", instruction.ip(), target);
                    } else {
                        debug!("Conditional branch at 0x{:x} with no direct target (indirect)", instruction.ip());
                    }
                    
                    if let Some(next_instr) = self.function.instructions.get(i + 1) {
                        leaders.insert(next_instr.ip());
                        debug!("Added fall-through target as leader: 0x{:x}", next_instr.ip());
                    }
                }
                FlowControl::Return => {
                    debug!("Found return instruction at 0x{:x}", instruction.ip());
                }
                _ => {}
            }
        }

        debug!("Basic block leader analysis complete:");
        debug!("  - Total leaders: {}", leaders.len());
        debug!("  - Unconditional branches: {}", branch_count);
        debug!("  - Conditional branches: {}", conditional_branch_count);
        
        let mut sorted_leaders: Vec<_> = leaders.iter().collect();
        sorted_leaders.sort();
        for leader in sorted_leaders {
            debug!("  - Leader at 0x{:x}", leader);
        }
        
        Ok(())
    }

    fn build_basic_blocks(&mut self) -> Result<()> {
        debug!("Building basic blocks from {} instructions", self.function.instructions.len());
        
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
        let mut blocks_created = 0;
        let mut total_instructions_processed = 0;
        
        for instruction in &self.function.instructions {
            let addr = instruction.ip();
            
            if leaders.contains(&addr) {
                if let Some(block) = current_block.take() {
                    debug!("Completed block {} with {} instructions (0x{:x} - 0x{:x})", 
                           block.id, block.instructions.len(), block.start_address, block.end_address);
                    self.cfg.blocks.insert(block.id, block);
                }
                
                let block_id = self.next_block_id;
                self.next_block_id += 1;
                blocks_created += 1;
                
                debug!("Starting new basic block {} at address 0x{:x}", block_id, addr);
                current_block = Some(BasicBlock::new(block_id, addr));
                
                if self.cfg.entry_block.is_none() {
                    self.cfg.entry_block = Some(block_id);
                    debug!("Set block {} as entry block", block_id);
                }
            }
            
            if let Some(ref mut block) = current_block {
                self.cfg.address_to_block.insert(addr, block.id);
                block.add_instruction(instruction.clone());
                total_instructions_processed += 1;
            }
        }
        
        if let Some(block) = current_block {
            debug!("Completed final block {} with {} instructions (0x{:x} - 0x{:x})", 
                   block.id, block.instructions.len(), block.start_address, block.end_address);
            self.cfg.blocks.insert(block.id, block);
        }

        info!("Basic block construction complete:");
        info!("  - Blocks created: {}", blocks_created);
        info!("  - Instructions processed: {}", total_instructions_processed);
        debug!("  - Address-to-block mappings: {}", self.cfg.address_to_block.len());
        
        Ok(())
    }

    fn build_control_flow_edges(&mut self) -> Result<()> {
        debug!("Building control flow edges between {} basic blocks", self.cfg.blocks.len());
        
        let block_ids: Vec<usize> = self.cfg.blocks.keys().copied().collect();
        let mut edges_created = 0;
        let mut unconditional_edges = 0;
        let mut conditional_edges = 0;
        let mut fallthrough_edges = 0;
        
        for block_id in block_ids {
            if let Some(block) = self.cfg.blocks.get(&block_id).cloned() {
                if let Some(last_instr) = block.instructions.last() {
                    let flow_control = last_instr.flow_control();
                    
                    debug!("Analyzing edges for block {} (last instruction: {:?} at 0x{:x})", 
                           block_id, flow_control, last_instr.ip());
                    
                    match flow_control {
                        FlowControl::UnconditionalBranch => {
                            if let Some(target) = self.get_branch_target(last_instr) {
                                if let Some(target_block_id) = self.cfg.address_to_block.get(&target) {
                                    debug!("Creating unconditional edge: {} -> {}", block_id, target_block_id);
                                    self.add_edge(block_id, *target_block_id);
                                    edges_created += 1;
                                    unconditional_edges += 1;
                                } else {
                                    warn!("Unconditional branch target 0x{:x} not found in any block", target);
                                }
                            }
                        }
                        FlowControl::ConditionalBranch => {
                            if let Some(target) = self.get_branch_target(last_instr) {
                                if let Some(target_block_id) = self.cfg.address_to_block.get(&target) {
                                    debug!("Creating conditional branch edge: {} -> {}", block_id, target_block_id);
                                    self.add_edge(block_id, *target_block_id);
                                    edges_created += 1;
                                    conditional_edges += 1;
                                } else {
                                    warn!("Conditional branch target 0x{:x} not found in any block", target);
                                }
                            }
                            
                            let next_addr = last_instr.ip() + last_instr.len() as u64;
                            if let Some(next_block_id) = self.cfg.address_to_block.get(&next_addr) {
                                debug!("Creating fall-through edge: {} -> {}", block_id, next_block_id);
                                self.add_edge(block_id, *next_block_id);
                                edges_created += 1;
                                fallthrough_edges += 1;
                            } else {
                                debug!("No fall-through block found at 0x{:x}", next_addr);
                            }
                        }
                        FlowControl::Return => {
                            debug!("Block {} ends with return - no outgoing edges", block_id);
                        }
                        _ => {
                            let next_addr = last_instr.ip() + last_instr.len() as u64;
                            if let Some(next_block_id) = self.cfg.address_to_block.get(&next_addr) {
                                debug!("Creating sequential edge: {} -> {}", block_id, next_block_id);
                                self.add_edge(block_id, *next_block_id);
                                edges_created += 1;
                                fallthrough_edges += 1;
                            }
                        }
                    }
                } else {
                    warn!("Block {} has no instructions", block_id);
                }
            }
        }
        
        info!("Control flow edge construction complete:");
        info!("  - Total edges created: {}", edges_created);
        debug!("  - Unconditional branch edges: {}", unconditional_edges);
        debug!("  - Conditional branch edges: {}", conditional_edges);
        debug!("  - Fall-through/sequential edges: {}", fallthrough_edges);
        
        Ok(())
    }

    fn add_edge(&mut self, from: usize, to: usize) {
        debug!("Adding edge: {} -> {}", from, to);
        
        if let Some(from_block) = self.cfg.blocks.get_mut(&from) {
            from_block.add_successor(to);
        } else {
            error!("Source block {} not found when adding edge", from);
        }
        
        if let Some(to_block) = self.cfg.blocks.get_mut(&to) {
            to_block.add_predecessor(from);
        } else {
            error!("Target block {} not found when adding edge", to);
        }
    }

    fn identify_exit_blocks(&mut self) {
        debug!("Identifying exit blocks in CFG");
        
        let mut exit_blocks = Vec::new();
        let mut return_blocks = 0;
        let mut no_successor_blocks = 0;
        
        for (block_id, block) in &self.cfg.blocks {
            if block.successors.is_empty() {
                debug!("Block {} has no successors", block_id);
                exit_blocks.push(*block_id);
                no_successor_blocks += 1;
            } else if let Some(last_instr) = block.instructions.last() {
                if last_instr.flow_control() == FlowControl::Return {
                    debug!("Block {} ends with return instruction", block_id);
                    if !exit_blocks.contains(block_id) {
                        exit_blocks.push(*block_id);
                    }
                    return_blocks += 1;
                }
            }
        }
        
        self.cfg.exit_blocks = exit_blocks;
        
        info!("Exit block identification complete:");
        info!("  - Total exit blocks: {}", self.cfg.exit_blocks.len());
        debug!("  - Blocks with return instructions: {}", return_blocks);
        debug!("  - Blocks with no successors: {}", no_successor_blocks);
        
        for exit_block in &self.cfg.exit_blocks {
            debug!("  - Exit block: {}", exit_block);
        }
    }

    fn get_branch_target(&self, instruction: &Instruction) -> Option<u64> {
        let target = match instruction.op0_kind() {
            OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16 => {
                Some(instruction.near_branch_target())
            }
            _ => {
                debug!("Instruction at 0x{:x} has non-direct branch target (op kind: {:?})", 
                       instruction.ip(), instruction.op0_kind());
                None
            }
        };
        
        if let Some(addr) = target {
            debug!("Resolved branch target for instruction at 0x{:x}: 0x{:x}", instruction.ip(), addr);
        }
        
        target
    }
}

pub fn lift(
    _pe_file: &crate::binary::pe::PeFile,
    functions: &[Function]
) -> Result<Vec<ControlFlowGraph>> {
    let mut cfgs = Vec::new();
    
    for function in functions {
        let mut builder = IrBuilder::new(function.clone());
        builder.build()?;
        let cfg = builder.into_cfg();
        cfgs.push(cfg);
    }
    
    info!("Lifted {} functions to IR", cfgs.len());
    Ok(cfgs)
}
