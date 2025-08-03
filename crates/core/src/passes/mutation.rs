use super::Pass;
use crate::function::RuntimeFunction;
use iced_x86::{Code, Instruction, MemoryOperand, OpKind};

pub struct MutationPass {}

impl MutationPass {
    pub fn new() -> Self {
        Self {}
    }
}

fn get_memory_operand(instruction: &Instruction) -> MemoryOperand {
    let mem_base = instruction.memory_base();
    let mem_index = instruction.memory_index();
    let mem_scale = instruction.memory_index_scale();
    let mem_displ = instruction.memory_displacement64();
    let mem_displ_size = instruction.memory_displ_size();
    let is_broadcast = instruction.is_broadcast();
    let mem_seg = instruction.segment_prefix();
    MemoryOperand::new(
        mem_base,
        mem_index,
        mem_scale,
        mem_displ as i64,
        mem_displ_size,
        is_broadcast,
        mem_seg,
    )
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Mutation Pass"
    }

    fn apply(&self, function: &mut RuntimeFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 3);

        for instruction in function.instructions.iter() {
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
                        (OpKind::Register, OpKind::Memory) => {
                            let dest_reg = instruction.op0_register();
                            let mem_base = instruction.memory_base();

                            if dest_reg == mem_base || dest_reg == instruction.memory_index() {
                                println!("Skipping mutation - dest reg {:?} used in memory operand: {:?}", dest_reg, instruction);
                                result.push(*instruction);
                                continue;
                            }

                            let src_mem = get_memory_operand(instruction);
                            
                            result.push(Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap());
                            result.push(Instruction::with2(Code::Add_r64_rm64, dest_reg, src_mem).unwrap());            
                        
                            println!("{}: {:?}", function.name, instruction);                
                        }

                        (OpKind::Memory, OpKind::Register) => {
                            let src_reg = instruction.op1_register();
                            let mem_base = instruction.memory_base();
                            let mem_index = instruction.memory_index();
                            
                            if src_reg == mem_base || src_reg == mem_index {
                                println!("Skipping mutation - src reg {:?} used in memory operand: {:?}", 
                                        src_reg, instruction);
                                result.push(*instruction);
                                continue;
                            }
                            
                            // Method 1: PUSH/POP pattern (safest)
                            result.push(Instruction::with1(Code::Push_r64, src_reg).unwrap());
                            
                            let mut pop_instr = *instruction;
                            pop_instr.set_code(Code::Pop_rm64);
                            result.push(pop_instr);
                            
                            println!("{}: {:?}", function.name, instruction);
                        }                        _ => {
                            result.push(*instruction);
                        }
                    }
                }
                _ => {
                    result.push(*instruction);
                }
            }
        }

        function.instructions = result;
        Ok(())
    }

    fn enabled_by_default(&self) -> bool {
        true
    }
}
