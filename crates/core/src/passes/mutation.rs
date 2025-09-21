use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction, OpKind};
use rand::Rng;

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

    fn mutate_mov(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

        match (op_kinds[0], op_kinds[1]) {
            (OpKind::Register, OpKind::Memory) => {
                let dest_reg = instruction.instruction.op0_register();
                let mem_base = instruction.instruction.memory_base();

                if dest_reg == mem_base || dest_reg == instruction.instruction.memory_index() {
                    result.push(instruction.clone());
                    return result;
                }

                let src_mem = instruction.get_memory_operand();

                if let Some(mut xor_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap(),
                ) {
                    xor_inst.set_id(instruction.get_id());
                    result.push(xor_inst);
                }

                if let Some(mut add_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Add_r64_rm64, dest_reg, src_mem).unwrap(),
                ) {
                    add_inst.set_id(instruction.get_id());
                    result.push(add_inst);
                }
            }
            (OpKind::Memory, OpKind::Register) => {
                let src_reg = instruction.instruction.op1_register();
                let mem_base = instruction.instruction.memory_base();

                if src_reg == mem_base || src_reg == instruction.instruction.memory_index() {
                    result.push(instruction.clone());
                    return result;
                }

                let dest_mem = instruction.get_memory_operand();

                if let Some(mut and_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::And_rm64_imm32, dest_mem, 0).unwrap(),
                ) {
                    and_inst.set_id(instruction.get_id());
                    result.push(and_inst);
                }

                if let Some(mut or_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Or_rm64_r64, dest_mem, src_reg).unwrap(),
                ) {
                    or_inst.set_id(instruction.get_id());
                    result.push(or_inst);
                }
            }
            _ => {
                result.push(instruction.clone());
            }
        }

        result
    }

    fn mutate_lea(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();

        if instruction.instruction.memory_displ_size() != 0 {
            let dest_reg = instruction.instruction.op0_register();
            let random_value = rand::rng().random_range(0..=i16::MAX) as i32;

            let displacement = instruction.instruction.memory_displacement64();
            let mut new_instruction = instruction.clone();
            new_instruction.instruction.set_memory_displacement64(displacement + random_value as u64);
            result.push(new_instruction);

            if let Some(pushf_instr) = self.create_instruction(
                context,
                Instruction::with(Code::Pushfq),
            ) {
                result.push(pushf_instr);
            }

            if let Some(sub_instr) = self.create_instruction(
                context,
                Instruction::with2(Code::Sub_rm64_imm32, dest_reg, random_value).unwrap(),
            ) {
                result.push(sub_instr);
            }

            if let Some(popfq_instr) = self.create_instruction(
                context,
                Instruction::with(Code::Popfq),
            ) {
                result.push(popfq_instr);
            }
        } else {
            result.push(instruction.clone());
        }

        result
    }

    fn mutate_xor(&self, instruction: &InstructionWithId, _context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();

        result.push(instruction.clone());

        result
    }

    fn mutate_call(&self, instruction: &InstructionWithId, _context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();

        result.push(instruction.clone());

        result
    }

    fn mutate_add(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

        match (op_kinds[0], op_kinds[1]) {
            (OpKind::Register, OpKind::Register) => {
                let dest_reg = instruction.instruction.op0_register();
                let src_reg = instruction.instruction.op1_register();

                if let Some(mut neg_inst) = self.create_instruction(
                    context,
                    Instruction::with1(Code::Neg_rm64, src_reg).unwrap(),
                ) {
                    neg_inst.set_id(instruction.get_id());
                    result.push(neg_inst);
                }

                if let Some(mut sub_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Sub_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    sub_inst.set_id(instruction.get_id());
                    result.push(sub_inst);
                }

                if let Some(mut neg_inst2) = self.create_instruction(
                    context,
                    Instruction::with1(Code::Neg_rm64, src_reg).unwrap(),
                ) {
                    neg_inst2.set_id(instruction.get_id());
                    result.push(neg_inst2);
                }
            }
            _ => {
                result.push(instruction.clone());
            }
        }

        result
    }
    
    fn mutate_or(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

        match (op_kinds[0], op_kinds[1]) {
            (OpKind::Register, OpKind::Register) => {
                let dest_reg = instruction.instruction.op0_register();
                let src_reg = instruction.instruction.op1_register();

                if let Some(mut and_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::And_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    and_inst.set_id(instruction.get_id());
                    result.push(and_inst);
                }

                if let Some(mut xor_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Xor_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    xor_inst.set_id(instruction.get_id());
                    result.push(xor_inst);
                }

                if let Some(mut xor_inst2) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Xor_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    xor_inst2.set_id(instruction.get_id());
                    result.push(xor_inst2);
                }
            }
            _ => {
                result.push(instruction.clone());
            }
        }

        result
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
                    let mut mutated = self.mutate_mov(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Lea_r64_m => {
                    let mut mutated = self.mutate_lea(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Xor_r64_rm64 | Code::Xor_rm64_r64 => {
                    let mut mutated = self.mutate_xor(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Call_rm64 => {
                    let mut mutated = self.mutate_call(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Add_r64_rm64 | Code::Add_rm64_r64 => {
                    let mut mutated = self.mutate_add(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Or_r64_rm64 | Code::Or_rm64_r64 => {
                    let mut mutated = self.mutate_or(instruction, &function.instruction_context);
                    result.append(&mut mutated);
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
