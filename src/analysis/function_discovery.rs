use crate::binary::pe::PeFile;
use anyhow::Result;
use tracing::{error, info, warn, debug};
use crate::binary::SectionOperations;
use iced_x86::{Decoder, DecoderOptions, Instruction, Formatter, NasmFormatter, FlowControl, Mnemonic, OpKind};
use std::collections::{HashSet, HashMap, VecDeque};
use crate::types::Function;

pub struct FunctionDiscovery {
    pe_file: PeFile,
    merged_sections: Vec<u8>,
    section_base_rva: u64,
    discovered_functions: HashMap<u64, Function>,
    pending_analysis: VecDeque<u64>,
}

#[allow(dead_code)]
impl FunctionDiscovery {
    pub fn new(pe_file: PeFile) -> Result<Self> {
        if !pe_file.is_loaded() {
            error!("PE file not loaded");
            return Err(anyhow::anyhow!("PE file not loaded"));
        }
        Ok(Self { 
            pe_file, 
            merged_sections: Vec::new(),
            section_base_rva: 0,
            discovered_functions: HashMap::new(),
            pending_analysis: VecDeque::new(),
        })
    }

    pub fn run(&mut self) -> Result<Vec<Function>> {
        let sections = self.pe_file.get_code_sections()
            .map_err(|e| anyhow::anyhow!("Failed to get code sections: {}", e))?;
        
        info!("Found {} code sections", sections.len());

        self.merge_sections()?;
        info!("Merged sections: 0x{:x} bytes", self.merged_sections.len());

        self.initialize_analysis_points()?;
        
        self.discover_functions()?;
        
        self.finalize_function_boundaries();

        Ok(self.discovered_functions.values().cloned().collect())
    }

    pub fn get_functions(&self) -> &HashMap<u64, Function> {
        &self.discovered_functions
    }

    pub fn get_function_at(&self, rva: u64) -> Option<&Function> {
        self.discovered_functions.get(&rva)
    }

    fn merge_sections(&mut self) -> Result<()> {
        let sections = self.pe_file.get_code_sections()
            .map_err(|e| anyhow::anyhow!("Failed to get code sections: {}", e))?;
        
        if sections.is_empty() {
            return Err(anyhow::anyhow!("No code sections found"));
        }

        self.section_base_rva = sections[0].0;
        
        for section in sections {
            let rva = section.0;
            let size = section.1;
            let data = self.pe_file.read(rva, size)
                .map_err(|e| anyhow::anyhow!("Failed to read section at RVA 0x{:x}: {}", rva, e))?;
            
            let current_end = self.section_base_rva + self.merged_sections.len() as u64;
            if rva > current_end {
                let gap_size = (rva - current_end) as usize;
                self.merged_sections.extend(vec![0u8; gap_size]);
                debug!("Padded gap of {} bytes between sections", gap_size);
            }
            
            self.merged_sections.extend_from_slice(&data);
        }
        
        Ok(())
    }

    fn initialize_analysis_points(&mut self) -> Result<()> {
        if let Ok(entry_point) = self.pe_file.get_entry_point() {
            info!("Entry point: 0x{:x}", entry_point);
            self.add_function_candidate(entry_point, "EntryPoint".to_string());
        }

        // TODO: add symbols from pdb if available
        // TODO: add other sources of functions

        self.scan_for_call_targets()?;

        Ok(())
    }

    fn add_function_candidate(&mut self, rva: u64, name: String) {
        if !self.discovered_functions.contains_key(&rva) && self.is_valid_code_address(rva) {
            let function = Function::new(name, rva);
            
            self.discovered_functions.insert(rva, function);
            self.pending_analysis.push_back(rva);
            debug!("Added function candidate at 0x{:x}", rva);
        }
    }

    fn is_valid_code_address(&self, rva: u64) -> bool {
        if rva < self.section_base_rva {
            return false;
        }
        
        let offset = (rva - self.section_base_rva) as usize;
        offset < self.merged_sections.len()
    }

    fn discover_functions(&mut self) -> Result<()> {
        let mut analyzed_addresses = HashSet::new();
        
        while let Some(function_rva) = self.pending_analysis.pop_front() {
            if analyzed_addresses.contains(&function_rva) {
                continue;
            }
            
            debug!("Analyzing function at 0x{:x}", function_rva);
            self.analyze_function(function_rva, &mut analyzed_addresses)?;
        }
        
        Ok(())
    }

    fn analyze_function(&mut self, start_rva: u64, analyzed: &mut HashSet<u64>) -> Result<()> {
        analyzed.insert(start_rva);
        
        let offset = (start_rva - self.section_base_rva) as usize;
        if offset >= self.merged_sections.len() {
            warn!("Function RVA 0x{:x} is outside merged sections", start_rva);
            return Ok(());
        }

        let mut instruction = Instruction::default();
        let mut basic_block_queue = VecDeque::new();
        let mut visited_blocks = HashSet::new();
        let mut visited_instructions = HashSet::<u64>::new();
        let mut call_targets = Vec::new();
        let mut function_instructions = Vec::new();
        
        basic_block_queue.push_back(start_rva);

        while let Some(block_start) = basic_block_queue.pop_front() {
            if visited_blocks.contains(&block_start) {
                continue;
            }
            visited_blocks.insert(block_start);

            let block_offset = (block_start - self.section_base_rva) as usize;
            if block_offset >= self.merged_sections.len() {
                continue;
            }
            
            let mut decoder = Decoder::with_ip(64, &self.merged_sections[block_offset..], block_start, DecoderOptions::NONE);

            loop {
                if !decoder.can_decode() {
                    break;
                }

                decoder.decode_out(&mut instruction);
                let current_ip = instruction.ip();

                if visited_instructions.contains(&current_ip) {
                    break;
                }
                visited_instructions.insert(current_ip);

                function_instructions.push(instruction.clone());

                debug!("0x{:x}: {}", current_ip, self.format_instruction(&instruction));

                let flow_control = instruction.flow_control();
                match flow_control {
                    FlowControl::Call => {
                        if let Some(target) = self.get_call_target(&instruction) {
                            if self.is_valid_code_address(target) {
                                call_targets.push((current_ip, target));
                            }
                        }
                    }
                    FlowControl::UnconditionalBranch => {
                        if let Some(target) = self.get_branch_target(&instruction) {
                            if self.is_valid_code_address(target) {
                                debug!("Following unconditional branch (tail call) to 0x{:x}", target);
                                let target_offset = (target - self.section_base_rva) as usize;
                                if target_offset < self.merged_sections.len() && !visited_instructions.contains(&target) {
                                    decoder = Decoder::with_ip(64, &self.merged_sections[target_offset..], target, DecoderOptions::NONE);
                                    continue;
                                }
                            }
                        }
                        break;
                    }
                    FlowControl::ConditionalBranch => {
                        if let Some(target) = self.get_branch_target(&instruction) {
                            if self.is_valid_code_address(target) && !visited_blocks.contains(&target) {
                                basic_block_queue.push_back(target);
                            }
                        }
                    }
                    FlowControl::Return => {
                        debug!("Found return instruction at 0x{:x}, ending basic block", current_ip);
                        break;
                    }
                    _ => {
                    }
                }

                if self.is_function_epilogue(&instruction) {
                    break;
                }
            }
        }

        if let Some(function) = self.discovered_functions.get_mut(&start_rva) {
            function_instructions.sort_by_key(|instr| instr.ip());
            function.instructions = function_instructions;
            debug!("Populated {} instructions for function at 0x{:x}", function.instructions.len(), start_rva);
        }

        for (caller_ip, target) in call_targets {
            if !self.discovered_functions.contains_key(&target) {
                let name = format!("sub_{:x}", target);
                self.add_function_candidate(target, name);
            }
            debug!("Call from 0x{:x} to 0x{:x}", caller_ip, target);
        }

        Ok(())
    }

    fn get_call_target(&self, instruction: &Instruction) -> Option<u64> {
        if instruction.flow_control() != FlowControl::Call {
            return None;
        }

        match instruction.op0_kind() {
            OpKind::NearBranch64 => Some(instruction.near_branch_target()),
            OpKind::NearBranch32 => Some(instruction.near_branch_target()),
            _ => None,
        }
    }

    fn get_branch_target(&self, instruction: &Instruction) -> Option<u64> {
        match instruction.op0_kind() {
            OpKind::NearBranch64 => Some(instruction.near_branch_target()),
            OpKind::NearBranch32 => Some(instruction.near_branch_target()),
            OpKind::NearBranch16 => Some(instruction.near_branch_target()),
            _ => None,
        }
    }

    fn is_function_epilogue(&self, instruction: &Instruction) -> bool {
        matches!(instruction.mnemonic(), 
            Mnemonic::Ret | 
            Mnemonic::Retf | 
            Mnemonic::Iret | 
            Mnemonic::Iretd | 
            Mnemonic::Iretq
        )
    }

    fn finalize_function_boundaries(&mut self) {
        let mut sorted_functions: Vec<_> = self.discovered_functions.keys().copied().collect();
        sorted_functions.sort();

        for i in 0..sorted_functions.len() {
            let current_rva = sorted_functions[i];
            let next_rva = if i + 1 < sorted_functions.len() {
                sorted_functions[i + 1]
            } else {
                self.section_base_rva + self.merged_sections.len() as u64
            };

            if let Some(function) = self.discovered_functions.get_mut(&current_rva) {
                function.size = next_rva - current_rva;
            }
        }
    }

    fn format_instruction(&self, instruction: &Instruction) -> String {
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();
        formatter.format(instruction, &mut output);
        output
    }

    fn scan_for_call_targets(&mut self) -> Result<()> {
        let mut candidates = Vec::new();
        let merged_sections = self.merged_sections.clone();
        let mut decoder = Decoder::new(64, &merged_sections, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            
            if instruction.flow_control() == FlowControl::Call {
                if let Some(target) = self.get_call_target(&instruction) {
                    if self.is_valid_code_address(target) && !self.discovered_functions.contains_key(&target) {
                        let name = format!("called_{:x}", target);
                        candidates.push((target, name));
                    }
                }
            }
        }
        
        for (target, name) in candidates {
            self.add_function_candidate(target, name);
        }
        
        info!("Found {} call targets", self.discovered_functions.len());
        Ok(())
    }

}