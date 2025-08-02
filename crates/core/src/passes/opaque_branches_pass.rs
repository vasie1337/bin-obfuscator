use super::Pass;
use iced_x86::{Code, Instruction, OpKind, Register, MemoryOperand};

pub struct OpaqueBranchesPass {
}

impl OpaqueBranchesPass {
    pub fn new() -> Self {
        Self {
        }
    }

}

fn get_memory_operand(instruction: &Instruction) -> MemoryOperand {
    let mem_base = instruction.memory_base();
    let mem_index = instruction.memory_index();
    let mem_scale = instruction.memory_index_scale();
    let mem_displ = instruction.memory_displacement64();
    let mem_seg = instruction.memory_segment();
    MemoryOperand::new(mem_base, mem_index, mem_scale, mem_displ as i64, 8, false, mem_seg)
}

impl Pass for OpaqueBranchesPass {
    fn name(&self) -> &'static str {
        "Opaque Branches Pass"
    }

    fn apply(&self, instructions: &[Instruction]) -> Vec<Instruction> {
        let mut result = Vec::with_capacity(instructions.len() * 3);

        for instruction in instructions.iter() {
            match instruction.code() {
                Code::Mov_r64_rm64 | Code::Mov_rm64_r64 => {
                    let op_kinds: Vec<OpKind> = instruction.op_kinds().collect();

                    match (op_kinds[0], op_kinds[1]) {
                        (OpKind::Register, OpKind::Register) => {
                            let dest_reg = instruction.op0_register();
                            let src_reg = instruction.op1_register();

                            result.push(
                                Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap(),
                            );
                            result.push(Instruction::with(Code::Clc));
                            result.push(
                                Instruction::with2(Code::Adcx_r64_rm64, dest_reg, src_reg).unwrap(),
                            );
                        }
                        (OpKind::Memory, OpKind::Register) => {
                            let src_reg = instruction.op1_register();
                            
                            let dest_mem = get_memory_operand(instruction);
                            
                            result.push(Instruction::with1(Code::Push_rm64, dest_mem).unwrap());
                            result.push(Instruction::with2(Code::Xchg_rm64_r64, dest_mem, src_reg).unwrap());
                            result.push(Instruction::with2(Code::Xchg_rm64_r64, dest_mem, src_reg).unwrap());
                            result.push(Instruction::with1(Code::Pop_rm64, dest_mem).unwrap());
                        }
	                    (OpKind::Register, OpKind::Memory) => {
	                        let dest_reg = instruction.op0_register();
                        
	                        let src_mem = get_memory_operand(instruction);
                        
	                        result.push(Instruction::with1(Code::Push_r64, Register::R11).unwrap());
                        
	                        result.push(Instruction::with2(Code::Lea_r64_m, Register::R11, src_mem).unwrap());
                        
	                        let indirect_mem = MemoryOperand::with_base(Register::R11);
	                        result.push(Instruction::with2(Code::Mov_r64_rm64, dest_reg, indirect_mem).unwrap());
                        
	                        result.push(Instruction::with1(Code::Pop_r64, Register::R11).unwrap());
	                    }
                        _ => {
                            result.push(*instruction);
                        }
                    }
                }
	            Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => {
                    let dest_reg = instruction.op0_register();
                    let original_displ = instruction.memory_displacement64();
                    
                    let random_offset = 0xEFA7u64;
                    let obfuscated_displ = original_displ.wrapping_add(random_offset);
                    
                    let mem_base = instruction.memory_base();
                    let mem_index = instruction.memory_index();
                    let mem_scale = instruction.memory_index_scale();
                    let mem_seg = instruction.memory_segment();
                    
                    let obfuscated_mem = MemoryOperand::new(
                        mem_base, 
                        mem_index, 
                        mem_scale, 
                        obfuscated_displ as i64, 
                        8, 
                        false, 
                        mem_seg
                    );
                    
                    result.push(Instruction::with(Code::Pushfq));
                    
                    result.push(Instruction::with2(Code::Lea_r64_m, dest_reg, obfuscated_mem).unwrap());

                    result.push(Instruction::with2(Code::Xchg_rm64_r64, dest_reg, dest_reg).unwrap());
                    result.push(Instruction::with2(Code::Xchg_rm64_r64, dest_reg, dest_reg).unwrap());

                    result.push(Instruction::with2(Code::Sub_rm64_imm32, dest_reg, random_offset as u32).unwrap());
                    
                    result.push(Instruction::with(Code::Popfq));
	            }
                _ => {
                    result.push(*instruction);
                }
            }
        }

        result
    }

    fn enabled_by_default(&self) -> bool {
        true
    }
}
