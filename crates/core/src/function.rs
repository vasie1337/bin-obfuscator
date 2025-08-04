use iced_x86::*;
use parsers::pdb::PDBFunction;
use parsers::pe::PEContext;

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

    // Update branch targets repsective to the new section base
    // we need to do this before shuffeling instructions around internally in the function
    // otherwise the auto bracnh fixing from iced_x86 will not work
    // for every relative instruction, not only jumps we need to update it if the address is in this function
    // this is to support indirect jumps and direct jumps
    pub fn fix_branches(&mut self, new_section_base: u32) {
        for instruction in self.instructions.iter_mut() {
            if instruction.is_ip_rel_memory_operand() {
                // FOr now only log this so we now what we need to fix
                println!("Found relative instruction: {:?}", instruction);
                // TODO: Fix this
            }
        }
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

        let mut decoder =
            Decoder::with_ip(64, &bytes, self.rva as u64, iced_x86::DecoderOptions::NONE);

        while decoder.can_decode() {
            let instruction = decoder.decode();

            match instruction.mnemonic() {
                Mnemonic::Ret => {
                    instructions.push(instruction);
                    break;
                }
                _ => {
                    instructions.push(instruction);
                }
            }
        }

        instructions.shrink_to_fit();

        self.instructions = instructions;

        Ok(())
    }

    pub fn encode(&self, rva: u64) -> Result<Vec<u8>, String> {
        let block = InstructionBlock::new(&self.instructions, rva);
        let result = match BlockEncoder::encode(64, block, BlockEncoderOptions::RETURN_RELOC_INFOS) {
            Ok(result) => result,
            Err(e) => return Err(e.to_string()),
        };
        
        // Debug: Print relocation information to understand what's being fixed
        if !result.reloc_infos.is_empty() {
            println!("Function at RVA {:#x} has {} relocations:", rva, result.reloc_infos.len());
            for reloc in &result.reloc_infos {
                println!("  Reloc at offset {:#x}, kind: {:?}", reloc.address, reloc.kind);
            }
        }
        
        Ok(result.code_buffer)
    }
}
