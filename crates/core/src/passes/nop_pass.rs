use common::info;
use iced_x86::{Instruction, Code};
use super::Pass;

pub struct NopPass {
    nop_count: usize,
}

impl NopPass {
    pub fn new() -> Self {
        Self {
            nop_count: 1,
        }
    }
    
    pub fn with_count(nop_count: usize) -> Self {
        Self {
            nop_count,
        }
    }
    
    fn create_nop() -> Instruction {
        Instruction::with(Code::Nopd)
    }
}

impl Pass for NopPass {
    fn name(&self) -> &'static str {
        "NOP Insertion Pass"
    }
    
    fn apply(&self, instructions: &[Instruction]) -> Vec<Instruction> {
        let mut result = Vec::with_capacity(instructions.len() * (1 + self.nop_count));
        
        for (i, instruction) in instructions.iter().enumerate() {
            result.push(*instruction);
            
            if i < instructions.len() - 1 {
                for _ in 0..self.nop_count {
                    result.push(Self::create_nop());
                }
            }
        }

        info!("NOP pass: Inserted {} NOP instructions", 
                     result.len() - instructions.len());

        result
    }
    
    fn enabled_by_default(&self) -> bool {
        true
    }
}
