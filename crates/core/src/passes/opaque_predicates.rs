//! Opaque Predicates pass.
//!
//! Inserts computational sequences that perform predictable operations
//! but add noise for static analysis. Uses stack-free LEA-based arithmetic
//! that doesn't modify flags.
//!
//! The key insight is that we need to avoid PUSH/POP entirely because
//! they can interfere with stack-based sequences created by other passes.

use super::Pass;
use super::utils::create_instruction;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, FlowControl, Instruction, MemoryOperand, Register};
use rand::Rng;

/// Pass that inserts opaque predicates to confuse static analysis.
pub struct OpaquePredicatesPass {
    /// Probability of inserting a predicate after each instruction (0.0 - 1.0)
    insertion_probability: f64,
}

impl OpaquePredicatesPass {
    pub fn new() -> Self {
        Self {
            insertion_probability: 0.05,
        }
    }

    #[allow(dead_code)]
    pub fn with_probability(probability: f64) -> Self {
        Self {
            insertion_probability: probability.clamp(0.0, 1.0),
        }
    }

    fn is_safe_insertion_point(
        instruction: &Instruction,
        next_instruction: Option<&Instruction>,
    ) -> bool {
        match instruction.flow_control() {
            FlowControl::Next => {}
            _ => return false,
        }

        let mnemonic = instruction.mnemonic();

        if mnemonic == iced_x86::Mnemonic::Push {
            return false;
        }

        if mnemonic == iced_x86::Mnemonic::Mov {
            if instruction.op0_kind() == iced_x86::OpKind::Memory
                && instruction.memory_base() == Register::RSP
            {
                return false;
            }
        }

        if mnemonic == iced_x86::Mnemonic::Lea {
            if instruction.op0_kind() == iced_x86::OpKind::Register
                && instruction.op_register(0) == Register::RSP
            {
                return false;
            }
            if instruction.is_ip_rel_memory_operand() {
                return false;
            }
        }

        if let Some(next) = next_instruction {
            for i in 0..next.op_count() {
                if next.op_kind(i) == iced_x86::OpKind::Register {
                    let reg = next.op_register(i);
                    if matches!(
                        reg,
                        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH
                    ) {
                        return false;
                    }
                }
                if next.op_kind(i) == iced_x86::OpKind::Memory {
                    if next.memory_base() == Register::RAX || next.memory_index() == Register::RAX {
                        return false;
                    }
                }
            }
        }

        true
    }

    fn insert_computation_predicate(
        &self,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();

        if let Ok(instr) = Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RSP, -8),
            Register::RAX,
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base(Register::RSP),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_index(Register::RAX, Register::RAX),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RSP, -8),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        result
    }

    fn insert_lea_chain_predicate(
        &self,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let offset: i64 = rand::rng().random_range(0x100_i64..=0x1000_i64);

        if let Ok(instr) = Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RSP, -8),
            Register::RAX,
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RSP, offset),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, -offset),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RSP, -8),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        result
    }

    fn insert_multi_lea_predicate(
        &self,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        let off1: i64 = rand::rng().random_range(0x40_i64..=0x200_i64);
        let off2: i64 = rand::rng().random_range(0x40_i64..=0x200_i64);

        if let Ok(instr) = Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RSP, -8),
            Register::RAX,
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RSP, off1),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, off2),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RAX, -(off1 + off2)),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        if let Ok(instr) = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RSP, -8),
        ) {
            if let Some(inst) = create_instruction(context, instr) {
                result.push(inst);
            }
        }

        result
    }

    fn insert_random_predicate(
        &self,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let choice = rand::rng().random_range(0..3);
        match choice {
            0 => self.insert_computation_predicate(context),
            1 => self.insert_lea_chain_predicate(context),
            _ => self.insert_multi_lea_predicate(context),
        }
    }
}

impl Pass for OpaquePredicatesPass {
    fn name(&self) -> &'static str {
        "OpaquePredicates"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 2);
        let mut rng = rand::rng();
        let instructions = &function.instructions;

        for (i, instruction) in instructions.iter().enumerate() {
            result.push(instruction.clone());

            let next = instructions.get(i + 1).map(|iw| &iw.instruction);

            if !Self::is_safe_insertion_point(&instruction.instruction, next) {
                continue;
            }

            if rng.random::<f64>() < self.insertion_probability {
                let predicate = self.insert_random_predicate(&function.instruction_context);
                result.extend(predicate);
            }
        }

        function.instructions = result;
        Ok(())
    }
}

impl Default for OpaquePredicatesPass {
    fn default() -> Self {
        Self::new()
    }
}
