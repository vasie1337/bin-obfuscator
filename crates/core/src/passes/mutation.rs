use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction, MemoryOperand, Register};
use rand::Rng;

pub struct MutationPass;

impl MutationPass {
    pub fn new() -> Self {
        Self
    }

    fn create_instruction(
        &self,
        context: &crate::instruction::InstructionContext,
        instruction: Instruction,
    ) -> Option<InstructionWithId> {
        let instruction = InstructionWithId {
            id: context.next_id(),
            instruction,
        };

        instruction
            .re_encode(0)
            .ok()
            .map(|instruction| InstructionWithId {
                id: context.next_id(),
                instruction,
            })
    }

    fn mutate_lea(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();

        if instruction.instruction.memory_displ_size() == 0 {
            result.push(instruction.clone());
            return result;
        }

        let dest_reg = instruction.instruction.op0_register();
        let displacement = instruction.instruction.memory_displacement64();
        
        let offset1: i64 = rand::rng().random_range(0x100_i64..=0x3FFF_i64);
        let offset2: i64 = rand::rng().random_range(0x100_i64..=0x3FFF_i64);
        let total_offset = offset1 + offset2;

        let mut lea1 = instruction.clone();
        lea1.instruction.set_memory_displacement64(displacement.wrapping_add(total_offset as u64));
        result.push(lea1);

        if let Some(lea2) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Lea_r64_m,
                dest_reg,
                MemoryOperand::with_base_displ(dest_reg, -offset1),
            )
            .unwrap(),
        ) {
            result.push(lea2);
        }

        if let Some(lea3) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Lea_r64_m,
                dest_reg,
                MemoryOperand::with_base_displ(dest_reg, -offset2),
            )
            .unwrap(),
        ) {
            result.push(lea3);
        }

        result
    }

    fn mutate_push(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let reg = instruction.instruction.op0_register();

        if let Some(mut mov_inst) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(Register::RSP, -8),
                reg,
            )
            .unwrap(),
        ) {
            mov_inst.set_id(instruction.get_id());
            result.push(mov_inst);
        }

        if let Some(lea_inst) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RSP,
                MemoryOperand::with_base_displ(Register::RSP, -8),
            )
            .unwrap(),
        ) {
            result.push(lea_inst);
        }

        result
    }

    fn mutate_pop(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let reg = instruction.instruction.op0_register();

        if let Some(mut mov_inst) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Mov_r64_rm64,
                reg,
                MemoryOperand::with_base(Register::RSP),
            )
            .unwrap(),
        ) {
            mov_inst.set_id(instruction.get_id());
            result.push(mov_inst);
        }

        if let Some(lea_inst) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RSP,
                MemoryOperand::with_base_displ(Register::RSP, 8),
            )
            .unwrap(),
        ) {
            result.push(lea_inst);
        }

        result
    }

    fn mutate_mov_imm64(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let dest_reg = instruction.instruction.op0_register();
        let imm = instruction.instruction.immediate64();

        if imm == 0 || imm == u64::MAX || imm < 0x200 {
            result.push(instruction.clone());
            return result;
        }

        let offset1: i64 = rand::rng().random_range(0x80_i64..=0x1FFF_i64);
        let offset2: i64 = rand::rng().random_range(0x80_i64..=0x1FFF_i64);
        let base_value = imm.wrapping_sub((offset1 + offset2) as u64);

        if let Some(mut mov_inst) = self.create_instruction(
            context,
            Instruction::with2(Code::Mov_r64_imm64, dest_reg, base_value).unwrap(),
        ) {
            mov_inst.set_id(instruction.get_id());
            result.push(mov_inst);
        }

        if let Some(lea1) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Lea_r64_m,
                dest_reg,
                MemoryOperand::with_base_displ(dest_reg, offset1),
            )
            .unwrap(),
        ) {
            result.push(lea1);
        }

        if let Some(lea2) = self.create_instruction(
            context,
            Instruction::with2(
                Code::Lea_r64_m,
                dest_reg,
                MemoryOperand::with_base_displ(dest_reg, offset2),
            )
            .unwrap(),
        ) {
            result.push(lea2);
        }

        result
    }

    fn mutate_shl(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let reg = instruction.instruction.op0_register();

        if let Some(mut add_inst) = self.create_instruction(
            context,
            Instruction::with2(Code::Add_r64_rm64, reg, reg).unwrap(),
        ) {
            add_inst.set_id(instruction.get_id());
            result.push(add_inst);
        }

        result
    }

    fn mutate_call(
        &self,
        instruction: &InstructionWithId,
        _context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        vec![instruction.clone()]
    }
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Mutation"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 3);

        for instruction in function.instructions.iter() {
            let mutated = match instruction.instruction.code() {
                Code::Lea_r64_m => self.mutate_lea(instruction, &function.instruction_context),

                Code::Push_r64 => self.mutate_push(instruction, &function.instruction_context),
                Code::Pop_r64 => self.mutate_pop(instruction, &function.instruction_context),

                Code::Mov_r64_imm64 => {
                    self.mutate_mov_imm64(instruction, &function.instruction_context)
                }
                Code::Shl_rm64_imm8 if instruction.instruction.immediate8() == 1 => {
                    self.mutate_shl(instruction, &function.instruction_context)
                }
                
                Code::Call_rm64 => self.mutate_call(instruction, &function.instruction_context),

                _ => vec![instruction.clone()],
            };

            result.extend(mutated);
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
