//! Arithmetic obfuscation pass.
//! 
//! Transforms arithmetic and data movement instructions:
//! - LEA displacement obfuscation (add random offset, compensate with extra LEAs)
//! - Constant splitting (split MOV imm into MOV + LEA chain)
//! - SHL by 1 → ADD reg, reg

use super::utils::create_instruction;
use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction, MemoryOperand};
use rand::Rng;

/// Pass that obfuscates arithmetic operations and constants.
pub struct ArithmeticPass;

impl ArithmeticPass {
    pub fn new() -> Self {
        Self
    }

    /// LEA displacement obfuscation with multi-step compensation.
    /// 
    /// ```text
    /// lea rax, [rbx + 0x100]
    /// ↓
    /// lea rax, [rbx + 0x100 + K1 + K2]
    /// lea rax, [rax - K1]
    /// lea rax, [rax - K2]
    /// ```
    /// 
    /// Creates a dependency chain that symbolic executors must track.
    fn mutate_lea(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();

        // Only mutate LEA with displacement
        if instruction.instruction.memory_displ_size() == 0 {
            result.push(instruction.clone());
            return result;
        }

        let dest_reg = instruction.instruction.op0_register();
        let displacement = instruction.instruction.memory_displacement64();
        
        // Generate two random offsets
        let offset1: i64 = rand::rng().random_range(0x100_i64..=0x3FFF_i64);
        let offset2: i64 = rand::rng().random_range(0x100_i64..=0x3FFF_i64);
        let total_offset = offset1 + offset2;

        // First LEA with modified displacement (keeps original ID)
        let mut lea1 = instruction.clone();
        lea1.instruction.set_memory_displacement64(
            displacement.wrapping_add(total_offset as u64)
        );
        result.push(lea1);

        // Second LEA: subtract offset1
        if let Some(lea2) = create_instruction(
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

        // Third LEA: subtract offset2
        if let Some(lea3) = create_instruction(
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

    /// MOV imm64 constant splitting.
    /// 
    /// ```text
    /// mov rax, 0x12345678
    /// ↓
    /// mov rax, (0x12345678 - K1 - K2)
    /// lea rax, [rax + K1]
    /// lea rax, [rax + K2]
    /// ```
    /// 
    /// Hides constants from static analysis by splitting them.
    fn mutate_mov_imm64(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let dest_reg = instruction.instruction.op0_register();
        let imm = instruction.instruction.immediate64();

        // Skip special values that shouldn't be obfuscated
        if imm == 0 || imm == u64::MAX || imm < 0x200 {
            result.push(instruction.clone());
            return result;
        }

        // Three-way split of the constant
        let offset1: i64 = rand::rng().random_range(0x80_i64..=0x1FFF_i64);
        let offset2: i64 = rand::rng().random_range(0x80_i64..=0x1FFF_i64);
        let base_value = imm.wrapping_sub((offset1 + offset2) as u64);

        // MOV with base value (keeps original ID)
        if let Some(mut mov_inst) = create_instruction(
            context,
            Instruction::with2(Code::Mov_r64_imm64, dest_reg, base_value).unwrap(),
        ) {
            mov_inst.set_id(instruction.get_id());
            result.push(mov_inst);
        }

        // LEA to add offset1
        if let Some(lea1) = create_instruction(
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

        // LEA to add offset2
        if let Some(lea2) = create_instruction(
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

    /// SHL by 1 → ADD reg, reg.
    /// 
    /// ```text
    /// shl rax, 1
    /// ↓
    /// add rax, rax
    /// ```
    /// 
    /// Both produce identical results and flags for shift by 1.
    fn mutate_shl_1(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let reg = instruction.instruction.op0_register();

        if let Some(mut add_inst) = create_instruction(
            context,
            Instruction::with2(Code::Add_r64_rm64, reg, reg).unwrap(),
        ) {
            add_inst.set_id(instruction.get_id());
            result.push(add_inst);
        }

        result
    }
}

impl Pass for ArithmeticPass {
    fn name(&self) -> &'static str {
        "Arithmetic"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 3);

        for instruction in function.instructions.iter() {
            let mutated = match instruction.instruction.code() {
                // LEA displacement obfuscation
                Code::Lea_r64_m => {
                    self.mutate_lea(instruction, &function.instruction_context)
                }
                
                // Constant splitting
                Code::Mov_r64_imm64 => {
                    self.mutate_mov_imm64(instruction, &function.instruction_context)
                }
                
                // SHL 1 → ADD
                Code::Shl_rm64_imm8 if instruction.instruction.immediate8() == 1 => {
                    self.mutate_shl_1(instruction, &function.instruction_context)
                }

                _ => vec![instruction.clone()],
            };

            result.extend(mutated);
        }

        function.instructions = result;
        Ok(())
    }
}

impl Default for ArithmeticPass {
    fn default() -> Self {
        Self::new()
    }
}

