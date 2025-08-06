use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction};

pub struct MutationPass {}

impl MutationPass {
    pub fn new() -> Self {
        Self {}
    }
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Mutation Pass"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let mut result = Vec::with_capacity(function.instructions.len() * 3);
        
        for instruction in function.instructions.iter() {
            
            let nop_instr = function.instruction_context.create_instruction(Instruction::with(Code::Int3));
            let re_encoded_nop_instr = nop_instr.re_encode(instruction.instruction.ip())?;
            
            result.push(InstructionWithId {
                id: function.instruction_context.next_id(),
                instruction: re_encoded_nop_instr,
            });

            result.push(InstructionWithId {
                id: instruction.id,
                instruction: instruction.instruction,
            });
        }

        function.instructions = result;

        Ok(())
    }

    fn enabled_by_default(&self) -> bool {
        true
    }
}