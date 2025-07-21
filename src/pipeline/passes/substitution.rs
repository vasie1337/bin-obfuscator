use crate::types::ControlFlowGraph;
use crate::lowerer::code_gen::CodeGenerator;
use crate::pipeline::passes::TransformationPass;
use iced_x86::{Instruction, Mnemonic, Register, OpKind, code_asm::*};
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

    fn register_to_asm64(&self, reg: Register) -> Result<AsmRegister64> {
        match reg {
            Register::RAX => Ok(rax),
            Register::RBX => Ok(rbx),
            Register::RCX => Ok(rcx),
            Register::RDX => Ok(rdx),
            Register::RSI => Ok(rsi),
            Register::RDI => Ok(rdi),
            Register::RBP => Ok(rbp),
            Register::RSP => Ok(rsp),
            Register::R8 => Ok(r8),
            Register::R9 => Ok(r9),
            Register::R10 => Ok(r10),
            Register::R11 => Ok(r11),
            Register::R12 => Ok(r12),
            Register::R13 => Ok(r13),
            Register::R14 => Ok(r14),
            Register::R15 => Ok(r15),
            Register::EAX => Ok(rax),
            Register::EBX => Ok(rbx),
            Register::ECX => Ok(rcx),
            Register::EDX => Ok(rdx),
            Register::ESI => Ok(rsi),
            Register::EDI => Ok(rdi),
            Register::EBP => Ok(rbp),
            _ => Err(anyhow::anyhow!("Unsupported register: {:?}", reg))
        }
    }

	fn substitute_mov(&self, instruction: &Instruction, code_gen: &mut CodeGenerator) -> Result<Vec<Instruction>> {
	    debug!("Substituting MOV instruction: {:?}", instruction);
	    
	    match (instruction.op0_kind(), instruction.op1_kind()) {
	        // mov reg, reg
	        (OpKind::Register, OpKind::Register) => {
	            let dest = self.register_to_asm64(instruction.op0_register())?;
	            let src = self.register_to_asm64(instruction.op1_register())?;

	            // Clear the destination register and copy source
	            code_gen.add_xor(dest, dest)?;
	            code_gen.add_or(dest, src)?;
	        }
	        // mov reg, immediate  
	        (OpKind::Register, OpKind::Immediate32) => {
	            let dest = self.register_to_asm64(instruction.op0_register())?;
	            let imm = instruction.immediate32() as i32;

	            // Clear the destination register and add immediate value
	            code_gen.add_xor(dest, dest)?;
	            code_gen.add_add_imm(dest, imm)?;
	        }
	        _ => {
	            return Err(anyhow::anyhow!("Unsupported MOV operand combination"));
	        }
	    }

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

    fn should_substitute(&self, instruction: &Instruction) -> bool {
        match instruction.mnemonic() {
            Mnemonic::Mov => true,
            _ => false,
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
                if self.should_substitute(instruction) {
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
                } else {
                    new_instructions.push(*instruction);
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
