use super::Pass;
use crate::function::RuntimeFunction;
use iced_x86::{Code, Instruction, OpKind};

pub struct MutationPass {}

impl MutationPass {
    pub fn new() -> Self {
        Self {}
    }
}

//fn get_memory_operand(instruction: &Instruction) -> MemoryOperand {
//    let mem_base = instruction.memory_base();
//    let mem_index = instruction.memory_index();
//    let mem_scale = instruction.memory_index_scale();
//    let mem_displ = instruction.memory_displacement64();
//    let mem_seg = instruction.memory_segment();
//    MemoryOperand::new(
//        mem_base,
//        mem_index,
//        mem_scale,
//        mem_displ as i64,
//        8,
//        false,
//        mem_seg,
//    )
//}

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
                        (OpKind::Memory, OpKind::Register) => {
                            //let src_reg = instruction.op1_register();
                            //let dest_mem = get_memory_operand(instruction);
                            //// Zero out the memory location
                            //result.push(Instruction::with2(Code::Xor_rm64_imm32, dest_mem, 0).unwrap());
                            //result.push(Instruction::with(Code::Clc));
                            //result.push(Instruction::with2(Code::Adc_rm64_r64, dest_mem, src_reg).unwrap());
                            //println!("{}: {:?}", function.name, instruction);
                        }
                        //(OpKind::Register, OpKind::Memory) => {
                        //    let dest_reg = instruction.op0_register();
                        //    let src_mem = get_memory_operand(instruction);
                        //
                        //    result.push(Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap());
                        //    result.push(Instruction::with(Code::Clc));
                        //    result.push(Instruction::with2(Code::Adcx_r64_rm64, dest_reg, src_mem).unwrap());
                        //}
                        _ => {
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
