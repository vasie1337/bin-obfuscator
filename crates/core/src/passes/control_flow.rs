//! Control flow obfuscation pass.
//! 
//! Transforms control flow instructions:
//! - Indirect calls (call reg) → LEA + PUSH + JMP sequence
//! 
//! This hides call patterns from simple analysis and makes
//! control flow graphs harder to reconstruct.

use super::utils::{create_instruction, is_extended_register};
use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction, MemoryOperand, OpKind, Register};

/// Pass that obfuscates control flow instructions.
pub struct ControlFlowPass;

impl ControlFlowPass {
    pub fn new() -> Self {
        Self
    }

    /// Obfuscate indirect calls (call reg) using explicit return address computation.
    /// 
    /// ```text
    /// call rax
    /// ↓
    /// lea r11, [rip + X]    ; r11 = return address
    /// push r11              ; push return address
    /// jmp rax               ; indirect jump to target
    /// ; return point        ; execution resumes here after RET
    /// ```
    /// 
    /// X = len(push r11) + len(jmp reg) = 4 or 5 bytes depending on register
    /// 
    /// R11 is used as scratch because it's caller-saved in the x64 ABI.
    /// The callee is allowed to clobber it anyway.
    fn mutate_call_reg(
        &self,
        instruction: &InstructionWithId,
        context: &crate::instruction::InstructionContext,
    ) -> Vec<InstructionWithId> {
        let mut result = Vec::new();
        
        // Only obfuscate register-indirect calls (call rax, call rbx, etc.)
        if instruction.instruction.op0_kind() != OpKind::Register {
            result.push(instruction.clone());
            return result;
        }
        
        let target_reg = instruction.instruction.op0_register();
        let original_id = instruction.get_id();
        
        // Can't use R11 as scratch if target is R11 or R10
        if target_reg == Register::R11 || target_reg == Register::R10 {
            result.push(instruction.clone());
            return result;
        }
        
        // Calculate offset for LEA [rip + offset]
        // Instruction sizes:
        // - push r11 = 41 53 = 2 bytes
        // - jmp rax..rdi = FF E0..E7 = 2 bytes
        // - jmp r8..r15 = 41 FF E0..E7 = 3 bytes (REX prefix)
        let jmp_size: i64 = if is_extended_register(target_reg) { 3 } else { 2 };
        let push_r11_size: i64 = 2;
        let offset = push_r11_size + jmp_size;
        
        // LEA R11, [RIP + offset]
        let lea_mem = MemoryOperand::new(
            Register::RIP,      // RIP-relative addressing
            Register::None,
            1,
            offset,
            8,
            false,
            Register::None,
        );
        
        if let Ok(lea_instr) = Instruction::with2(Code::Lea_r64_m, Register::R11, lea_mem) {
            if let Some(mut lea_inst) = create_instruction(context, lea_instr) {
                lea_inst.set_id(original_id);
                result.push(lea_inst);
            } else {
                result.push(instruction.clone());
                return result;
            }
        } else {
            result.push(instruction.clone());
            return result;
        }
        
        // PUSH R11
        if let Ok(push_instr) = Instruction::with1(Code::Push_r64, Register::R11) {
            if let Some(push_inst) = create_instruction(context, push_instr) {
                result.push(push_inst);
            }
        }
        
        // JMP target_reg
        if let Ok(jmp_instr) = Instruction::with1(Code::Jmp_rm64, target_reg) {
            if let Some(jmp_inst) = create_instruction(context, jmp_instr) {
                result.push(jmp_inst);
            }
        }
        
        result
    }
}

impl Pass for ControlFlowPass {
    fn name(&self) -> &'static str {
        "ControlFlow"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 2);

        for instruction in function.instructions.iter() {
            let mutated = match instruction.instruction.code() {
                Code::Call_rm64 => {
                    self.mutate_call_reg(instruction, &function.instruction_context)
                }
                _ => vec![instruction.clone()],
            };

            result.extend(mutated);
        }

        function.instructions = result;
        Ok(())
    }
}

impl Default for ControlFlowPass {
    fn default() -> Self {
        Self::new()
    }
}

