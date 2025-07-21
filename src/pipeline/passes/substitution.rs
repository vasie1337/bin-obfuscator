use crate::types::ControlFlowGraph;
use crate::lowerer::code_gen::CodeGenerator;
use crate::pipeline::passes::TransformationPass;
use iced_x86::{Instruction, Mnemonic, code_asm::*};
use anyhow::Result;
use tracing::{debug, info, warn};

pub struct SubstitutionPass {
    pub bitness: u32,
}

impl SubstitutionPass {
    pub fn new(bitness: u32) -> Self {
        Self {
            bitness,
        }
    }

    fn substitute_mov(&self, instruction: &Instruction, code_gen: &mut CodeGenerator) -> Result<Vec<Instruction>> {
        debug!("Substituting MOV instruction: {:?}", instruction);
        
        code_gen.add_xor(rax, rax)?;
        code_gen.add_add(rax, rbx)?;
        
        Ok(code_gen.take_instructions())
    }

    fn substitute_instruction(&self, instruction: &Instruction) -> Result<Vec<Instruction>> {
        let mut code_gen = CodeGenerator::new(self.bitness)?;
        
        match instruction.mnemonic() {
            Mnemonic::Mov => self.substitute_mov(instruction, &mut code_gen),
            _ => {
                Ok(vec![*instruction])
            }
        }
    }
}

impl TransformationPass for SubstitutionPass {
    fn name(&self) -> &'static str {
        "substitution"
    }

    fn transform(&self, cfg: &mut ControlFlowGraph) -> Result<()> {
        info!("Running substitution pass on {} basic blocks", cfg.blocks.len());
        
        let mut substitutions_made = 0;

        for (block_id, block) in cfg.blocks.iter_mut() {
            debug!("Processing basic block {}", block_id);
            
            let mut new_instructions = Vec::new();
            
            for instruction in &block.instructions {
                match self.substitute_instruction(instruction) {
                    Ok(substituted) => {
                        new_instructions.extend(substituted);
                        substitutions_made += 1;
                        debug!("Substituted instruction: {:?}", instruction);
                    }
                    Err(e) => {
                        warn!("Failed to substitute instruction {:?}: {}", instruction, e);
                        new_instructions.push(*instruction);
                    }
                }
            }
            
            block.instructions = new_instructions;
            
            if let Some(last_instr) = block.instructions.last() {
                block.end_address = last_instr.ip() + last_instr.len() as u64;
            }
        }
        
        info!("Substitution pass complete: {} substitutions made", substitutions_made);
        Ok(())
    }
}
