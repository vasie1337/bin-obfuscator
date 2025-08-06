use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction, OpKind};

pub struct MutationPass;

impl MutationPass {
    pub fn new() -> Self {
        Self
    }

    fn create_instruction(&self, context: &crate::instruction::InstructionContext, instruction: Instruction) -> Option<InstructionWithId> {
        let instruction = InstructionWithId {
            id: context.next_id(),
            instruction,
        };

        instruction.re_encode(0).ok().map(|instruction| InstructionWithId {
            id: context.next_id(),
            instruction,
        })
    }
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Mutation"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 3);

        for instruction in function.instructions.iter() {
            match instruction.instruction.code() {
                Code::Mov_r64_rm64 | Code::Mov_rm64_r64 => {
                    let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

                    match (op_kinds[0], op_kinds[1]) {
                        (OpKind::Register, OpKind::Register) => {
                            let dest_reg = instruction.instruction.op0_register();
                            let src_reg = instruction.instruction.op1_register();

                            if let Some(mut pushf_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with(Code::Pushfq),
                            ) {
                                pushf_inst.set_id(instruction.get_id());
                                result.push(pushf_inst);
                            }
                            
                            if let Some(xor_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap(),
                            ) {
                                result.push(xor_inst);
                            }
                    
                            if let Some(clc_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with(Code::Clc),
                            ) {
                                result.push(clc_inst);
                            }
                    
                            if let Some(adcx_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with2(Code::Adcx_r64_rm64, dest_reg, src_reg).unwrap(),
                            ) {
                                result.push(adcx_inst);
                            }

                            if let Some(popfq_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with(Code::Popfq),
                            ) {
                                result.push(popfq_inst);
                            }
                        }
                        (OpKind::Register, OpKind::Memory) => {
                            let dest_reg = instruction.instruction.op0_register();
                            let mem_base = instruction.instruction.memory_base();

                            if dest_reg == mem_base || dest_reg == instruction.instruction.memory_index() {
                                result.push(instruction.clone());
                                continue;
                            }

                            let src_mem = instruction.get_memory_operand();
                            
                            if let Some(mut xor_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap(),
                            ) {
                                xor_inst.set_id(instruction.get_id());
                                result.push(xor_inst);
                            }

                            if let Some(mut add_inst) = self.create_instruction(
                                &function.instruction_context,
                                Instruction::with2(Code::Add_r64_rm64, dest_reg, src_mem).unwrap(),
                            ) {
                                add_inst.set_id(instruction.get_id());
                                result.push(add_inst);
                            }
                        }
                        _ => {
                            result.push(instruction.clone());
                        }
                    }
                }
                _ => {
                    result.push(instruction.clone());
                }
            }
        }

        function.instructions = result;
        Ok(())
    }
}

impl Default for MutationPass {
    fn default() -> Self {
        Self::new()
    }
}
