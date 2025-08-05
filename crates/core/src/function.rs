use crate::pdb::PDBFunction;
use crate::pe::PEContext;
use common::{debug, warn};
use iced_x86::*;
use std::fmt::{Debug, Display, Error, Formatter};

#[derive(Clone)]
pub struct OriginalFunctionState {
    pub rva: u32,
    pub size: u32,
    pub instructions: Vec<Instruction>,
}

pub struct ObfuscatorFunction {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub instructions: Vec<Instruction>,
    pub original: Option<OriginalFunctionState>,
    pub unwind_info_address: Option<u32>,
}

impl ObfuscatorFunction {
    pub fn new(pdb_function: &PDBFunction) -> Self {
        Self {
            name: pdb_function.name.clone(),
            rva: pdb_function.rva,
            size: pdb_function.size,
            instructions: vec![],
            original: None,
            unwind_info_address: None,
        }
    }

    pub fn update_rva(&mut self, rva: u32) {
        self.rva = rva;
    }

    pub fn update_size(&mut self, size: u32) {
        self.size = size;
    }

    pub fn capture_original_state(&mut self) {
        if self.original.is_some() {
            warn!(
                "Original state already captured for function {}, skipping",
                self.name
            );
            return;
        }

        debug!(
            "Capturing original state for function {} (RVA: {:#x}, size: {}, instructions: {})",
            self.name,
            self.rva,
            self.size,
            self.instructions.len()
        );

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
        debug!(
            "Decoding function {} at RVA {:#x} with size {}",
            self.name, self.rva, self.size
        );

        let bytes = pe_context
            .read_data_at_rva(self.rva, self.size as usize)
            .map_err(|e| {
                format!(
                    "Failed to read function bytes at RVA {:#x}: {}",
                    self.rva, e
                )
            })?;

        debug!("Read {} bytes for function {}", bytes.len(), self.name);

        let mut instructions = Vec::new();
        let mut decoder =
            Decoder::with_ip(64, &bytes, self.rva as u64, iced_x86::DecoderOptions::NONE);

        let mut invalid_instriction_found = false;

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                invalid_instriction_found = true;
                warn!("Invalid instruction found at RVA {:#x}", instruction.ip());
                break;
            }
            instructions.push(instruction);
        }

        if invalid_instriction_found {
            return Err(format!(
                "Invalid instruction found in function {}",
                self.name
            ));
        }

        instructions.shrink_to_fit();

        debug!(
            "Successfully decoded function {} into {} instructions",
            self.name,
            instructions.len()
        );

        self.instructions = instructions;

        Ok(())
    }

    pub fn encode(&self, rva: u64) -> Result<Vec<u8>, String> {
        debug!(
            "Encoding function {} with {} instructions at RVA {:#x}",
            self.name,
            self.instructions.len(),
            rva
        );

        let block = InstructionBlock::new(&self.instructions, rva);
        let result = match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
            Ok(result) => result,
            Err(e) => {
                return Err(format!(
                    "Failed to encode function {}: {}",
                    self.name,
                    e.to_string()
                ));
            }
        };

        debug!(
            "Successfully encoded function {} into {} bytes",
            self.name,
            result.code_buffer.len()
        );

        Ok(result.code_buffer)
    }
}

impl Display for ObfuscatorFunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "name: {}, rva: {:#x}, size: {}, instructions: {}",
            self.name,
            self.rva,
            self.size,
            self.instructions.len()
        )
    }
}

impl Debug for ObfuscatorFunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "name: {}, rva: {:#x}, size: {}, instructions: {}",
            self.name,
            self.rva,
            self.size,
            self.instructions.len()
        )
    }
}
