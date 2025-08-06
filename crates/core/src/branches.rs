use crate::{function::ObfuscatorFunction, instruction::InstructionWithId};
use common::{debug, warn};
use iced_x86::*;

#[derive(Clone, Debug)]
pub struct BranchInfo {
    pub source_id: usize,
    pub target_id: usize,
    pub original_target: u64,
}

pub struct BranchManager;

impl BranchManager {
    pub fn new() -> Self {
        Self
    }

    pub fn get_branch_target(instruction: &Instruction) -> u32 {
        instruction.near_branch_target() as u32
    }

    pub fn set_branch_target(instruction: &mut Instruction, target_rva: u32) -> Result<(), String> {
        let op_kind = instruction.op0_kind();
        match op_kind {
            OpKind::NearBranch16 => instruction.set_near_branch16(target_rva as u16),
            OpKind::NearBranch32 => instruction.set_near_branch32(target_rva),
            OpKind::NearBranch64 => instruction.set_near_branch64(target_rva as u64),
            _ => return Err(format!("Invalid branch operand kind: {op_kind:#?}")),
        }
        Ok(())
    }

    pub fn build_branch_map(
        &self,
        instructions: &[InstructionWithId],
        function_rva: u32,
        function_size: u32,
    ) -> Vec<BranchInfo> {
        let mut branch_map = Vec::new();

        for inst_with_id in instructions {
            let instruction = &inst_with_id.instruction;

            if !self.is_branch_instruction(instruction) {
                continue;
            }

            let target_rva = Self::get_branch_target(instruction);
            debug!("{instruction}");
            debug!("Target RVA: {target_rva:#x}");

            if target_rva < function_rva || target_rva >= function_rva + function_size {
                debug!(
                    "Branch at RVA {:#x} targets outside function (target: {target_rva:#x}, function: {function_rva:#x}-{:#x})",
                    instruction.ip(),
                    function_rva + function_size,
                );
                continue;
            }

            if let Some(target_inst) = instructions
                .iter()
                .find(|inst| inst.instruction.ip() == target_rva as u64)
            {
                debug!(
                    "Target instruction: {:#?}",
                    target_inst.instruction
                );
                debug!("================================================");

                branch_map.push(BranchInfo {
                    source_id: inst_with_id.id,
                    target_id: target_inst.id,
                    original_target: target_rva as u64,
                });
            } else {
                warn!(
                    "Target instruction not found for internal branch at RVA {:#x} (target: {target_rva:#x})",
                    instruction.ip(),
                );
                debug!("{instruction}");
            }
        }

        branch_map
    }

    pub fn fix_branches(
        &self,
        instructions: &mut [InstructionWithId],
        branch_map: &[BranchInfo],
    ) -> Result<(), String> {
        for branch_info in branch_map {
            let target_inst = instructions
                .iter()
                .find(|inst| inst.id == branch_info.target_id)
                .ok_or_else(|| {
                    format!(
                        "Target instruction with ID {} not found",
                        branch_info.target_id
                    )
                })?;

            let target_ip = target_inst.instruction.ip() as u32;
            let target_str = target_inst.instruction.to_string();

            let source_inst = instructions
                .iter_mut()
                .find(|inst| inst.id == branch_info.source_id)
                .ok_or_else(|| {
                    format!(
                        "Source instruction with ID {} not found",
                        branch_info.source_id
                    )
                })?;

            debug!(
                "Fixing branch from {:#x} to {:#x}",
                source_inst.instruction.ip(),
                target_ip
            );
            debug!(
                "Source instruction: {:#?}",
                source_inst.instruction
            );
            debug!("Target instruction: {target_str}");
            debug!("================================================");

            Self::set_branch_target(&mut source_inst.instruction, target_ip)?;
        }

        Ok(())
    }

    fn is_branch_instruction(&self, instruction: &Instruction) -> bool {
        matches!(
            instruction.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        )
    }
}

impl Default for BranchManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ObfuscatorFunction {
    pub fn get_branch_target(&self, instruction: &Instruction) -> u32 {
        BranchManager::get_branch_target(instruction)
    }

    pub fn set_branch_target(
        &self,
        instruction: &mut Instruction,
        target_rva: u32,
    ) -> Result<(), String> {
        BranchManager::set_branch_target(instruction, target_rva)
    }

    pub fn build_branch_map(&mut self) {
        let branch_manager = BranchManager::new();
        self.branch_map = branch_manager.build_branch_map(&self.instructions, self.rva, self.size);
    }

    pub fn fix_branches(&mut self) -> Result<(), String> {
        let branch_manager = BranchManager::new();
        branch_manager.fix_branches(&mut self.instructions, &self.branch_map)
    }
}
