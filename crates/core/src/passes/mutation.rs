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

                if let Some(pushf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Pushfq),
                ) {
                    result.push(pushf_inst);
                }

                if let Some(clc_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Clc),
                ) {
                    result.push(clc_inst);
                }

                if let Some(mut adc_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Adc_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    adc_inst.set_id(instruction.get_id());
                    result.push(adc_inst);
                }

                if let Some(popf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Popfq),
                ) {
                    result.push(popf_inst);
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

                if let Some(pushf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Pushfq),
                ) {
                    result.push(pushf_inst);
                }

                if let Some(mut andn_inst) = self.create_instruction(
                    context,
                    Instruction::with3(Code::VEX_Andn_r64_r64_rm64, dest_reg, dest_reg, src_reg).unwrap(),
                ) {
                    andn_inst.set_id(instruction.get_id());
                    result.push(andn_inst);
                }

                if let Some(mut blsi_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::VEX_Blsi_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    blsi_inst.set_id(instruction.get_id());
                    result.push(blsi_inst);
                }

                if let Some(mut tzcnt_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Tzcnt_r64_rm64, dest_reg, src_reg).unwrap(),
                ) {
                    tzcnt_inst.set_id(instruction.get_id());
                    result.push(tzcnt_inst);
                }

                if let Some(popf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Popfq),
                ) {
                    result.push(popf_inst);
                }
            }
            _ => {
                result.push(instruction.clone());
            }
        }

        result
    }

    fn mutate_inc(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

        match op_kinds[0] {
            OpKind::Register => {
                let reg = instruction.instruction.op0_register();

                if let Some(pushf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Pushfq),
                ) {
                    result.push(pushf_inst);
                }

                if let Some(clc_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Clc),
                ) {
                    result.push(clc_inst);
                }

                if let Some(mut adc_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Adc_rm64_imm8, reg, 1).unwrap(),
                ) {
                    adc_inst.set_id(instruction.get_id());
                    result.push(adc_inst);
                }

                if let Some(popf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Popfq),
                ) {
                    result.push(popf_inst);
                }
            }
            _ => {
                result.push(instruction.clone());
            }
        }

        result
    }

    fn mutate_dec(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

        match op_kinds[0] {
            OpKind::Register => {
                let reg = instruction.instruction.op0_register();

                if let Some(pushf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Pushfq),
                ) {
                    result.push(pushf_inst);
                }

                if let Some(clc_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Clc),
                ) {
                    result.push(clc_inst);
                }

                if let Some(mut sbb_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Sbb_rm64_imm8, reg, 1).unwrap(),
                ) {
                    sbb_inst.set_id(instruction.get_id());
                    result.push(sbb_inst);
                }

                if let Some(popf_inst) = self.create_instruction(
                    context,
                    Instruction::with(Code::Popfq),
                ) {
                    result.push(popf_inst);
                }
            }
            _ => {
                result.push(instruction.clone());
            }
        }

        result
    }

    fn mutate_push(&self, instruction: &InstructionWithId, context: &crate::instruction::InstructionContext) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let op_kinds: Vec<OpKind> = instruction.instruction.op_kinds().collect();

        match op_kinds[0] {
            OpKind::Register => {
                let reg = instruction.instruction.op0_register();

                if let Some(mut mov_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Mov_rm64_r64, iced_x86::MemoryOperand::new(iced_x86::Register::RSP, iced_x86::Register::None, 1, -8, 8, false, iced_x86::Register::None), reg).unwrap(),
                ) {
                    mov_inst.set_id(instruction.get_id());
                    result.push(mov_inst);
                }

                if let Some(mut sub_inst) = self.create_instruction(
                    context,
                    Instruction::with2(Code::Sub_rm64_imm8, iced_x86::Register::RSP, 8).unwrap(),
                ) {
                    sub_inst.set_id(instruction.get_id());
                    result.push(sub_inst);
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
                Code::Lea_r64_m => {
                    let mut mutated = self.mutate_lea(instruction, &function.instruction_context);
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
                Code::Inc_rm64 => {
                    let mut mutated = self.mutate_inc(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Dec_rm64 => {
                    let mut mutated = self.mutate_dec(instruction, &function.instruction_context);
                    result.append(&mut mutated);
                }
                Code::Push_r64 => {
                    let mut mutated = self.mutate_push(instruction, &function.instruction_context);
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
