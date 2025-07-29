use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, Instruction, InstructionBlock};
use parsers::pe::PEContext;

pub struct RuntimeFunction {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub instructions: Vec<Instruction>,
}

impl RuntimeFunction {
    pub fn new(name: String, rva: u32, size: u32) -> Self {
        Self {
            name,
            rva,
            size,
            instructions: vec![],
        }
    }

    pub fn update_rva(&mut self, rva: u32) {
        self.rva = rva;
    }

    pub fn update_size(&mut self, size: u32) {
        self.size = size;
    }

    pub fn decode(&mut self, pe_context: &PEContext) -> Result<(), String> {
        let bytes = pe_context
            .read_data_at_rva(self.rva, self.size as usize)
            .map_err(|e| {
                format!(
                    "Failed to read function bytes at RVA {:#x}: {}",
                    self.rva, e
                )
            })?;

        let estimated_instruction_count = (bytes.len() / 3).max(16);
        let mut instructions = Vec::with_capacity(estimated_instruction_count);

        let mut decoder = Decoder::with_ip(
            64,
            &bytes,
            self.rva as u64,
            iced_x86::DecoderOptions::NONE,
        );

        while decoder.can_decode() {
            let instruction = decoder.decode();
            instructions.push(instruction);
        }

        instructions.shrink_to_fit();

        self.instructions = instructions;

        Ok(())
    }

    pub fn encode(&self, rva: u64) -> Result<Vec<u8>, String> {
        let block = InstructionBlock::new(&self.instructions, rva);
        let bytes = match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
            Ok(bytes) => bytes.code_buffer,
            Err(e) => return Err(e.to_string()),
        };
        Ok(bytes)
    }
}
