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

#[derive(Clone)]
pub struct ObfuscatorFunction {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub instructions: Vec<InstructionWithId>,
    pub original: Option<OriginalFunctionState>,
    pub branch_map: Vec<BranchInfo>,
    pub next_id: usize,
}

#[derive(Clone, Debug)]
pub struct BranchInfo {
    pub source_id: usize,
    pub target_id: usize,
    pub original_target: u64,
}

#[derive(Clone)]
pub struct InstructionWithId {
    pub id: usize,
    pub instruction: Instruction,
}

impl ObfuscatorFunction {
    pub fn new(pdb_function: &PDBFunction) -> Self {
        Self {
            name: pdb_function.name.clone(),
            rva: pdb_function.rva,
            size: pdb_function.size,
            instructions: vec![],
            original: None,
            branch_map: vec![],
            next_id: 0,
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

        let original_instructions: Vec<Instruction> = self.instructions.iter().map(|inst| inst.instruction).collect();
        self.original = Some(OriginalFunctionState {
            rva: self.rva,
            size: self.size,
            instructions: original_instructions,
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
        if let Some(orig) = &self.original {
            &orig.instructions
        } else {
            // For current instructions, we need to extract just the Instruction part
            // This is a temporary solution - ideally we'd store original as Vec<InstructionWithId> too
            panic!("Cannot get original instructions when original state is not captured")
        }
    }

    pub fn get_branch_target(&self, instruction: &Instruction) -> u32 {
        instruction.near_branch_target() as u32
    }

    pub fn set_branch_target(&self, instruction: &mut Instruction, target_rva: u32) {
		let op_kind = instruction.op0_kind();
		match op_kind {
			OpKind::NearBranch16 => instruction.set_near_branch16(target_rva as u16),
			OpKind::NearBranch32 => instruction.set_near_branch32(target_rva as u32),
			OpKind::NearBranch64 => instruction.set_near_branch64(target_rva as u64),
			_ => (),
		}
	}

    pub fn build_branch_map(&mut self) {
        for inst_with_id in &self.instructions {
            let instruction = &inst_with_id.instruction;
            if instruction.flow_control() == FlowControl::ConditionalBranch || instruction.flow_control() == FlowControl::UnconditionalBranch {
                let target_rva = self.get_branch_target(instruction);
                debug!("{}", instruction.to_string());
                debug!("Target RVA: {:#x}", target_rva);
                
                // Check if the target is within the current function boundaries
                if target_rva < self.rva || target_rva >= self.rva + self.size {
                    debug!("Branch at RVA {:#x} targets outside function (target: {:#x}, function: {:#x}-{:#x})", 
                           instruction.ip(), target_rva, self.rva, self.rva + self.size);
                    continue;
                }
                
                let target_inst_with_id = self.instructions.iter().find(|inst| inst.instruction.ip() == target_rva as u64);
                if target_inst_with_id.is_none() {
                    warn!("Target instruction not found for internal branch at RVA {:#x}", instruction.ip());
                    debug!("{}", instruction.to_string());
                    debug!("Target RVA: {:#x}", target_rva);
                    continue;
                }
                let target_instruction = &target_inst_with_id.unwrap().instruction;
                debug!("Target instruction: {}", target_instruction.to_string());
                debug!("================================================");
                self.branch_map.push(BranchInfo {
                    source_id: inst_with_id.id,
                    target_id: target_inst_with_id.unwrap().id,
                    original_target: target_rva as u64,
                });
            }
        }
    }

    pub fn fix_branches(&mut self) {
        for branch_info in &self.branch_map {
            let target_inst = self.instructions.iter().find(|inst| inst.id == branch_info.target_id);
            if target_inst.is_none() {
                warn!("Target instruction with ID {} not found", branch_info.target_id);
                continue;
            }
            let target_ip = target_inst.unwrap().instruction.ip() as u32;
            let target_str = target_inst.unwrap().instruction.to_string();
            
            let source_inst = self.instructions.iter_mut().find(|inst| inst.id == branch_info.source_id);
            if source_inst.is_none() {
                warn!("Source instruction with ID {} not found", branch_info.source_id);
                continue;
            }
            let source_inst = source_inst.unwrap();
            
            let op_kind = source_inst.instruction.op0_kind();

            debug!("Fixing branch from {:#x} to {:#x}", source_inst.instruction.ip(), target_ip);
            debug!("Source instruction: {}", source_inst.instruction.to_string());
            debug!("Target instruction: {}", target_str);
            debug!("================================================");

            match op_kind {
                OpKind::NearBranch16 => source_inst.instruction.set_near_branch16(target_ip as u16),
                OpKind::NearBranch32 => source_inst.instruction.set_near_branch32(target_ip as u32),
                OpKind::NearBranch64 => source_inst.instruction.set_near_branch64(target_ip as u64),
                _ => (),
            }
        }
    }

    pub fn analyze(&mut self) -> Result<(), String> {
        debug!("Analyzing function {}", self.name);
        self.build_branch_map();
        Ok(())
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
                debug!("Invalid instruction found at RVA {:#x}", instruction.ip());
                break;
            }
            instructions.push(InstructionWithId {
                id: self.next_id,
                instruction,
            });
            self.next_id += 1;
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

    pub fn adjust_instruction_addrs(code: &mut [InstructionWithId], start_addr: u64) {
        let mut new_ip = start_addr;
        for inst_with_id in code.iter_mut() {
            inst_with_id.instruction.set_ip(new_ip);
            new_ip = inst_with_id.instruction.next_ip();
        }
    }
    
    pub fn encode(&mut self, rva: u64) -> Result<Vec<u8>, String> {
        debug!(
            "Encoding function {} with {} instructions at RVA {:#x}",
            self.name,
            self.instructions.len(),
            rva
        );

        Self::adjust_instruction_addrs(&mut self.instructions, rva);

        self.fix_branches();

        let instructions: Vec<Instruction> = self.instructions.iter().map(|inst| inst.instruction).collect();

        //for inst in instructions.iter() {
        //    println!("{}", inst.to_string());
        //}

        let block = InstructionBlock::new(&instructions, rva);
        
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