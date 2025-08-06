use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use common::debug;
use iced_x86::{Code, FlowControl, Instruction};
use rand::Rng;

/// Mutation pass that applies various obfuscation techniques to function instructions
pub struct MutationPass {
    nop_insertion_rate: f64,
    junk_insertion_rate: f64,
}

impl MutationPass {
    pub fn new() -> Self {
        Self {
            nop_insertion_rate: 0.3,  // Insert NOPs 30% of the time
            junk_insertion_rate: 0.1, // Insert junk instructions 10% of the time
        }
    }

    pub fn with_rates(nop_rate: f64, junk_rate: f64) -> Self {
        Self {
            nop_insertion_rate: nop_rate.clamp(0.0, 1.0),
            junk_insertion_rate: junk_rate.clamp(0.0, 1.0),
        }
    }

    /// Inserts a NOP instruction
    fn create_nop_instruction(
        &self,
        context: &crate::instruction::InstructionContext,
        ip: u64,
    ) -> Result<InstructionWithId, String> {
        let nop_instr = context.create_instruction(Instruction::with(Code::Nopd));
        let re_encoded_nop = nop_instr.re_encode(ip)?;

        Ok(InstructionWithId {
            id: context.next_id(),
            instruction: re_encoded_nop,
        })
    }

    /// Inserts a junk instruction that doesn't affect program flow
    fn create_junk_instruction(
        &self,
        context: &crate::instruction::InstructionContext,
        ip: u64,
    ) -> Result<InstructionWithId, String> {
        let mut rng = rand::rng();

        // Choose a random junk instruction type
        let junk_instr = match rng.random_range(0..2) {
            0 => Instruction::with(Code::Nopd), // NOP instruction
            _ => Instruction::with(Code::Nopd), // fallback to NOP
        };

        let inst_with_id = context.create_instruction(junk_instr);
        let re_encoded = inst_with_id.re_encode(ip)?;

        Ok(InstructionWithId {
            id: context.next_id(),
            instruction: re_encoded,
        })
    }

    /// Checks if we can safely insert instructions before this instruction
    fn can_insert_before(&self, instruction: &Instruction) -> bool {
        // Don't insert before branch targets or call targets
        // This is a simple check - in a real implementation you'd want more sophisticated analysis
        !matches!(
            instruction.flow_control(),
            FlowControl::Call
                | FlowControl::Return
                | FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
        )
    }
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Code Mutation"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let original_count = function.instructions.len();
        let mut result = Vec::with_capacity(function.instructions.len() * 2);
        let mut rng = rand::rng();
        let mut insertions = 0;

        debug!(
            "Applying mutation pass to function {} with {} instructions",
            function.name, original_count
        );

        for instruction in function.instructions.iter() {
            // Decide whether to insert junk instructions before this one
            if self.can_insert_before(&instruction.instruction) {
                // Insert NOP
                if rng.random::<f64>() < self.nop_insertion_rate {
                    if let Ok(nop_inst) = self.create_nop_instruction(
                        &function.instruction_context,
                        instruction.instruction.ip(),
                    ) {
                        result.push(nop_inst);
                        insertions += 1;
                    }
                }

                // Insert junk instruction
                if rng.random::<f64>() < self.junk_insertion_rate {
                    if let Ok(junk_inst) = self.create_junk_instruction(
                        &function.instruction_context,
                        instruction.instruction.ip(),
                    ) {
                        result.push(junk_inst);
                        insertions += 1;
                    }
                }
            }

            // Add the original instruction
            result.push(instruction.clone());
        }

        function.instructions = result;

        debug!(
            "Mutation pass completed: inserted {} junk instructions into function {} ({} -> {} instructions)",
            insertions,
            function.name,
            original_count,
            function.instructions.len()
        );

        Ok(())
    }

    fn enabled_by_default(&self) -> bool {
        true
    }
}

impl Default for MutationPass {
    fn default() -> Self {
        Self::new()
    }
}
