//! Common utilities shared across mutation passes.

use crate::instruction::{InstructionContext, InstructionWithId};
use iced_x86::{Instruction, Register};

/// Helper to create and validate instructions.
pub fn create_instruction(
    context: &InstructionContext,
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

/// Check if a register is an extended register (R8-R15) which requires REX prefix.
/// Extended registers need an extra byte in instruction encoding.
pub fn is_extended_register(reg: Register) -> bool {
    matches!(
        reg,
        Register::R8 | Register::R9 | Register::R10 | Register::R11 |
        Register::R12 | Register::R13 | Register::R14 | Register::R15 |
        Register::R8D | Register::R9D | Register::R10D | Register::R11D |
        Register::R12D | Register::R13D | Register::R14D | Register::R15D |
        Register::R8W | Register::R9W | Register::R10W | Register::R11W |
        Register::R12W | Register::R13W | Register::R14W | Register::R15W |
        Register::R8L | Register::R9L | Register::R10L | Register::R11L |
        Register::R12L | Register::R13L | Register::R14L | Register::R15L
    )
}

/// Get a scratch register that doesn't conflict with the given registers.
/// Prefers caller-saved (volatile) registers.
#[allow(dead_code)]
pub fn get_scratch_register(avoid: &[Register]) -> Register {
    let candidates = [
        Register::R11, // Most preferred - always volatile
        Register::R10,
        Register::R9,
        Register::R8,
    ];
    
    for &reg in &candidates {
        if !avoid.contains(&reg) {
            return reg;
        }
    }
    Register::R11 // Fallback
}

