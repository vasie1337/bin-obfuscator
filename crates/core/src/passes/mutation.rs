use super::Pass;
use crate::function::ObfuscatorFunction;
use crate::instruction::InstructionWithId;
use iced_x86::{Code, Instruction};

pub struct MutationPass;

impl MutationPass {
    pub fn new() -> Self {
        Self
    }

    fn create_nop(&self, context: &crate::instruction::InstructionContext, ip: u64) -> Option<InstructionWithId> {
        let nop = context.create_instruction(Instruction::with(Code::Nopd));
        nop.re_encode(ip).ok().map(|instruction| InstructionWithId {
            id: context.next_id(),
            instruction,
        })
    }
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Mutation"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        let result: Vec<_> = function.instructions
            .iter()
            .enumerate()
            .flat_map(|(i, inst)| {
                let mut instructions = Vec::with_capacity(2);
                
                if i % 2 == 0 {
                    if let Some(nop) = self.create_nop(&function.instruction_context, inst.instruction.ip()) {
                        instructions.push(nop);
                    }
                }
                
                instructions.push(inst.clone());
                instructions
            })
            .collect();

        function.instructions = result;
        Ok(())
    }
}

impl Default for MutationPass {
    fn default() -> Self {
        Self::new()
    }
}
