//! Stack operation obfuscation pass.
//! 
//! Transforms stack operations into explicit sequences:
//! - PUSH → MOV [rsp-8], reg + LEA rsp, [rsp-8]
//! - POP → MOV reg, [rsp] + LEA rsp, [rsp+8]
//! 
//! Uses LEA for stack adjustment to avoid flag modification.

use super::utils::create_instruction;
use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

/// Pass that expands PUSH/POP into explicit stack operations.
pub struct StackPass;

impl StackPass {
    pub fn new() -> Self {
        Self
    }

    /// PUSH to explicit stack operations.
    /// 
    /// ```text
    /// push rax
    /// ↓
    /// mov [rsp-8], rax    ; store value below stack
    /// lea rsp, [rsp-8]    ; adjust stack pointer (flag-safe)
    /// ```
    fn mutate_push(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let reg = instruction.instruction.op0_register();

        // MOV [RSP-8], reg (keeps original ID for branch targeting)
        if let Some(mut mov_inst) = create_instruction(
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

        // LEA RSP, [RSP-8] - flag-safe stack adjustment
        if let Some(lea_inst) = create_instruction(
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

    /// POP to explicit stack operations.
    /// 
    /// ```text
    /// pop rax
    /// ↓
    /// mov rax, [rsp]      ; load value from stack
    /// lea rsp, [rsp+8]    ; adjust stack pointer (flag-safe)
    /// ```
    fn mutate_pop(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let reg = instruction.instruction.op0_register();

        // MOV reg, [RSP] (keeps original ID)
        if let Some(mut mov_inst) = create_instruction(
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

        // LEA RSP, [RSP+8]
        if let Some(lea_inst) = create_instruction(
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
}

impl Pass for StackPass {
    fn name(&self) -> &'static str {
        "Stack"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 2);

        for instruction in function.instructions.iter() {
            let mutated = match instruction.instruction.code() {
                Code::Push_r64 => {
                    self.mutate_push(instruction, &function.instruction_context)
                }
                Code::Pop_r64 => {
                    self.mutate_pop(instruction, &function.instruction_context)
                }
                _ => vec![instruction.clone()],
            };

            result.extend(mutated);
        }

        function.instructions = result;
        Ok(())
    }
}

impl Default for StackPass {
    fn default() -> Self {
        Self::new()
    }
}

