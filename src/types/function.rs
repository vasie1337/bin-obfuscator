use iced_x86::Instruction;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub rva: u64,
    pub size: u64,
    pub instructions: Vec<Instruction>,
}

impl Function {
    pub fn new(name: String, rva: u64) -> Self {
        Self { name, rva, size: 0, instructions: Vec::new() }
    }
}
