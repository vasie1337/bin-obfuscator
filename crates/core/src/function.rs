use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, Instruction, InstructionBlock};
use parsers::pdb::PDBFunction;
use parsers::pe::PEContext;

pub struct RuntimeFunction {
    pub pdb_function: PDBFunction,
    pub instructions: Vec<Instruction>,
}

impl RuntimeFunction {
    pub fn new(pdb_function: PDBFunction) -> Self {
        Self {
            pdb_function,
            instructions: vec![],
        }
    }

    pub fn decode(&mut self, pe_context: &PEContext) -> Result<(), String> {
        let bytes = pe_context
            .read_data_at_rva(self.pdb_function.rva, self.pdb_function.size as usize)
            .map_err(|e| {
                format!(
                    "Failed to read function bytes at RVA {:#x}: {}",
                    self.pdb_function.rva, e
                )
            })?;

        let estimated_instruction_count = (bytes.len() / 3).max(16);
        let mut instructions = Vec::with_capacity(estimated_instruction_count);

        let mut decoder = Decoder::with_ip(
            64,
            &bytes,
            self.pdb_function.rva as u64,
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
}
