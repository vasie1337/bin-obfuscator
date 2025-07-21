use crate::types::ControlFlowGraph;
use crate::lowerer::code_gen::CodeGenerator;
use crate::pipeline::passes::TransformationPass;
use iced_x86::{Instruction, code_asm::*};
use anyhow::Result;
use tracing::{debug, info, warn};
use rand::Rng;

pub struct OpaqueBranchesPass {
    pub bitness: u32,
    pub insertion_probability: f64,
}

impl OpaqueBranchesPass {
    pub fn new(bitness: u32) -> Self {
        Self {
            bitness,
            insertion_probability: 0.3, // 30% chance by default
        }
    }
    
    pub fn with_probability(bitness: u32, probability: f64) -> Self {
        Self {
            bitness,
            insertion_probability: probability.clamp(0.0, 1.0),
        }
    }

    fn create_simple_opaque_branch(&self) -> Result<Vec<Instruction>> {
        let mut code_gen = CodeGenerator::new(self.bitness)?;
        let value = rand::thread_rng().r#gen_range(1..1000) as u64;
        
        // Simple always-true predicate: set rax to value, then compare rax with itself
        let mut skip_label = code_gen.create_label();


        code_gen.add_push(rax)?;
        code_gen.add_mov_reg_imm(rax, value)?;
        code_gen.add_cmp(rax, rax)?;
        code_gen.add_pop(rax)?;
        
        // Create a label and jump if equal (always taken)
        code_gen.add_je(skip_label)?;

        // Add dead code (never executed)
        code_gen.add_nop()?;
        
        // Set the skip label
        code_gen.set_label(&mut skip_label)?;
        
        code_gen.assemble(0)?; // TODO - Get rva of original instruction

        Ok(code_gen.take_instructions())
    }

    fn should_insert_opaque_branch(&self) -> bool {
        let mut rng = rand::thread_rng();
        rng.r#gen::<f64>() < self.insertion_probability
    }
}

impl TransformationPass for OpaqueBranchesPass {
    fn name(&self) -> &'static str {
        "opaque_branches"
    }

    fn transform(&self, cfg: &mut ControlFlowGraph) -> Result<()> {
        info!("Running opaque branches pass on {} basic blocks", cfg.blocks.len());
        
        let mut branches_inserted = 0;

        for (block_id, block) in cfg.blocks.iter_mut() {
            debug!("Processing basic block {}", block_id);
            
            if !self.should_insert_opaque_branch() {
                continue;
            }
            
            // Insert at the beginning of the block for simplicity
            let insertion_point = 0;

            match self.create_simple_opaque_branch() {
                Ok(opaque_instructions) => {
                    // Insert the opaque branch instructions at the beginning
                    let mut new_instructions = opaque_instructions;
                    new_instructions.extend_from_slice(&block.instructions);
                    
                    block.instructions = new_instructions;
                    branches_inserted += 1;
                    
                    debug!("Inserted opaque branch in basic block {}", block_id);
                    
                    // Update end address if needed
                    if let Some(last_instr) = block.instructions.last() {
                        block.end_address = last_instr.ip() + last_instr.len() as u64;
                    }
                }
                Err(e) => {
                    warn!("Failed to create opaque branch for block {}: {}", block_id, e);
                }
            }
        }
        
        info!("Opaque branches pass complete: {} branches inserted", branches_inserted);
        Ok(())
    }
} 