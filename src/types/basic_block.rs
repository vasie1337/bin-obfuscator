use iced_x86::Instruction;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

impl BasicBlock {
    pub fn new(id: usize, start_address: u64) -> Self {
        Self {
            id,
            start_address,
            end_address: start_address,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    pub fn add_instruction(&mut self, instruction: Instruction) {
        self.end_address = instruction.ip() + instruction.len() as u64;
        self.instructions.push(instruction);
    }

    pub fn add_successor(&mut self, successor_id: usize) {
        if !self.successors.contains(&successor_id) {
            self.successors.push(successor_id);
        }
    }

    pub fn add_predecessor(&mut self, predecessor_id: usize) {
        if !self.predecessors.contains(&predecessor_id) {
            self.predecessors.push(predecessor_id);
        }
    }
}