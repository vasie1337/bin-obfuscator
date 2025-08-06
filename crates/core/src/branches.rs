use crate::function::ObfuscatorFunction;
use common::{debug, warn};
use iced_x86::*;

#[derive(Clone, Debug)]
pub struct BranchInfo {
    pub source_id: usize,
    pub target_id: usize,
    pub original_target: u64,
}

impl ObfuscatorFunction {
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
}