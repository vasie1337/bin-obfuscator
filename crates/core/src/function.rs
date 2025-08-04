use iced_x86::*;
use parsers::pdb::PDBFunction;
use parsers::pe::PEContext;
use std::fmt::{Display, Formatter, Error};
#[derive(Clone)]
pub struct OriginalFunctionState {
    pub rva: u32,
    pub size: u32,
    pub instructions: Vec<Instruction>,
}

pub struct RuntimeFunction {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub instructions: Vec<Instruction>,
    pub original: Option<OriginalFunctionState>,
}

impl RuntimeFunction {
    pub fn new(pdb_function: &PDBFunction) -> Self {
        Self {
            name: pdb_function.name.clone(),
            rva: pdb_function.rva,
            size: pdb_function.size,
            instructions: vec![],
            original: None,
        }
    }

    pub fn update_rva(&mut self, rva: u32) {
        self.rva = rva;
    }

    pub fn update_size(&mut self, size: u32) {
        self.size = size;
    }

    pub fn capture_original_state(&mut self) {
        self.original = Some(OriginalFunctionState {
            rva: self.rva,
            size: self.size,
            instructions: self.instructions.clone(),
        });
    }

    pub fn get_original(&self) -> Option<&OriginalFunctionState> {
        self.original.as_ref()
    }

    pub fn get_original_rva(&self) -> u32 {
        self.original
            .as_ref()
            .map(|orig| orig.rva)
            .unwrap_or(self.rva)
    }

    pub fn get_original_size(&self) -> u32 {
        self.original
            .as_ref()
            .map(|orig| orig.size)
            .unwrap_or(self.size)
    }

    pub fn get_original_instructions(&self) -> &Vec<Instruction> {
        self.original
            .as_ref()
            .map(|orig| &orig.instructions)
            .unwrap_or(&self.instructions)
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

        let mut instructions = Vec::new();
        let mut decoder = Decoder::with_ip(64, &bytes, self.rva as u64, iced_x86::DecoderOptions::NONE);

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
        let result = match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
            Ok(result) => result,
            Err(e) => return Err(e.to_string()),
        };
        
        Ok(result.code_buffer)
    }
}

impl Display for RuntimeFunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "name: {}, rva: {:#x}, size: {}, instructions: {}", self.name, self.rva, self.size, self.instructions.len())
    }
}