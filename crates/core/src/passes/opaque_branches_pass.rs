use iced_x86::{Instruction, Code, Register};
use super::Pass;


pub struct OpaqueBranchesPass {
}

impl OpaqueBranchesPass {
    pub fn new() -> Self {
        Self {
        }
    }

    // Creates an opaque predicate that always evaluates to true but is hard to analyze statically
    fn create_opaque_branch_sequence(&self, label_id: u64) -> Vec<Instruction> {
        let mut instructions = Vec::new();
        
        instructions.push(Instruction::with(Code::Pushfq));
        
        instructions.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());
        
        //// XOR EAX with itself (always results in 0, sets ZF=1)
        instructions.push(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap());
        //
        //// Restore flags to make analysis harder
        instructions.push(Instruction::with(Code::Popfq));
        //
        //// Save flags again for our opaque condition
        instructions.push(Instruction::with(Code::Pushfq));
        //
        //// Create another opaque condition - move 1 to ECX and test it (always non-zero)
        instructions.push(Instruction::with1(Code::Push_r64, Register::RCX).unwrap());
        instructions.push(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, 1u32).unwrap());
        instructions.push(Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX).unwrap());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap());
        
        // Always taken branch (JNZ after testing 1, which clears ZF, so JNZ will jump)
        instructions.push(Instruction::with_branch(Code::Jae_rel32_64, label_id).unwrap());
        
        // Dead code that should never execute 
        instructions.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());

        instructions.push(Instruction::with_branch(Code::Jne_rel32_64, label_id).unwrap());
        
        // XOR EAX with itself (always results in 0, sets ZF=1)
        instructions.push(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap());
        
        // Restore flags to make analysis harder
        instructions.push(Instruction::with(Code::Popfq));

        instructions.push(Instruction::with1(Code::Push_r64, Register::RAX).unwrap());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RAX).unwrap());

        instructions.push(Instruction::with_branch(Code::Jne_rel32_64, label_id).unwrap());

        instructions.push(Instruction::with_branch(Code::Jne_rel32_64, label_id).unwrap()); // Jump to the same label as other branches
        
        // XOR EAX with itself (always results in 0, sets ZF=1)
        instructions.push(Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).unwrap());
        
        // Restore flags to make analysis harder
        instructions.push(Instruction::with(Code::Popfq));

        instructions.push(Instruction::with_branch(Code::Jne_rel32_64, label_id).unwrap());
        
        // Label for the always-taken branch (this is where execution continues)
        let mut label_instr = Instruction::with(Code::Nopd);
        label_instr.set_ip(label_id);
        instructions.push(label_instr);
        
        // Restore flags
        instructions.push(Instruction::with(Code::Popfq));
        
        instructions
    }

}

impl Pass for OpaqueBranchesPass {
    fn name(&self) -> &'static str {
        "Opaque Branches Pass"
    }
    
    fn apply(&self, instructions: &[Instruction]) -> Vec<Instruction> {
        let mut result = Vec::with_capacity(instructions.len() * 3);
        let mut label_counter = 0x1000u64; // Start labels at a high offset to avoid conflicts
        
        for (i, instruction) in instructions.iter().enumerate() {            
            if i < instructions.len() - 1 && i % 15 == 0 { // Every 15th instruction for simple branches
                let label_id = label_counter;
                label_counter += 1;
                
                let opaque_sequence = self.create_opaque_branch_sequence(label_id);
                result.extend(opaque_sequence);
            }
            
            result.push(*instruction);
        }

        result
    }
    
    fn enabled_by_default(&self) -> bool {
        true
    }
}
