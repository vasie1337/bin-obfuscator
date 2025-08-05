use super::Pass;
use crate::function::ObfuscatorFunction;
use common::debug;
use iced_x86::{Code, Instruction, MemoryOperand, OpKind};

pub struct MutationPass {}

impl MutationPass {
    pub fn new() -> Self {
        Self {}
    }
}

fn get_memory_operand(instruction: &Instruction) -> MemoryOperand {
    let mem_base = instruction.memory_base();
    let mem_index = instruction.memory_index();
    let mem_scale = instruction.memory_index_scale();
    let mem_displ = instruction.memory_displacement64();
    let mem_displ_size = instruction.memory_displ_size();
    let is_broadcast = instruction.is_broadcast();
    let mem_seg = instruction.segment_prefix();
    MemoryOperand::new(
        mem_base,
        mem_index,
        mem_scale,
        mem_displ as i64,
        mem_displ_size,
        is_broadcast,
        mem_seg,
    )
}

impl Pass for MutationPass {
    fn name(&self) -> &'static str {
        "Mutation Pass"
    }

    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String> {
        debug!(
            "Starting mutation pass on function {} with {} instructions",
            function.name,
            function.instructions.len()
        );

        let mut result = Vec::with_capacity(function.instructions.len() * 3);
        let mut mov_reg_reg_mutations = 0;
        let mut mov_reg_mem_mutations = 0;
        let mut mov_mem_reg_mutations = 0;
        let mut lea_mutations = 0;
        let mut skipped_instructions = 0;

        for instruction in function.instructions.iter_mut() {
            match instruction.code() {
                Code::Mov_r64_rm64 | Code::Mov_rm64_r64 => {
                    let op_kinds: Vec<OpKind> = instruction.op_kinds().collect();

                    match (op_kinds[0], op_kinds[1]) {
                        (OpKind::Register, OpKind::Register) => {
                            mov_reg_reg_mutations += 1;
                            let dest_reg = instruction.op0_register();
                            let src_reg = instruction.op1_register();

                            let mut xor_instr =
                                Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap();
                            xor_instr.set_ip(instruction.ip());
                            result.push(xor_instr);

                            let mut clc_instr = Instruction::with(Code::Clc);
                            clc_instr.set_ip(instruction.ip() + 1);
                            result.push(clc_instr);

                            let mut adcx_instr =
                                Instruction::with2(Code::Adcx_r64_rm64, dest_reg, src_reg).unwrap();
                            adcx_instr.set_ip(instruction.ip() + 2);
                            result.push(adcx_instr);
                        }
                        (OpKind::Register, OpKind::Memory) => {
                            let dest_reg = instruction.op0_register();
                            let mem_base = instruction.memory_base();

                            if dest_reg == mem_base || dest_reg == instruction.memory_index() {
                                result.push(*instruction);
                                skipped_instructions += 1;
                                continue;
                            }

                            mov_reg_mem_mutations += 1;
                            let src_mem = get_memory_operand(instruction);

                            let mut xor_instr =
                                Instruction::with2(Code::Xor_r64_rm64, dest_reg, dest_reg).unwrap();
                            xor_instr.set_ip(instruction.ip());
                            result.push(xor_instr);

                            let mut clc_instr = Instruction::with(Code::Clc);
                            clc_instr.set_ip(instruction.ip() + 1);
                            result.push(clc_instr);

                            let mut adcx_instr =
                                Instruction::with2(Code::Adcx_r64_rm64, dest_reg, src_mem).unwrap();
                            adcx_instr.set_ip(instruction.ip() + 2);
                            result.push(adcx_instr);
                        }
                        (OpKind::Memory, OpKind::Register) => {
                            let src_reg = instruction.op1_register();
                            let mem_base = instruction.memory_base();
                            let mem_index = instruction.memory_index();

                            if src_reg == mem_base || src_reg == mem_index {
                                result.push(*instruction);
                                skipped_instructions += 1;
                                continue;
                            }

                            mov_mem_reg_mutations += 1;
                            let mut push_instr =
                                Instruction::with1(Code::Push_r64, src_reg).unwrap();
                            push_instr.set_ip(instruction.ip());
                            result.push(push_instr);

                            let mut pop_instr = *instruction;
                            pop_instr.set_code(Code::Pop_rm64);
                            pop_instr.set_ip(instruction.ip() + 1);
                            result.push(pop_instr);
                        }
                        _ => {
                            result.push(*instruction);
                            skipped_instructions += 1;
                        }
                    }
                }
                Code::Lea_r64_m => {
                    if instruction.memory_displ_size() != 0 {
                        lea_mutations += 1;
                        let dest_reg = instruction.op0_register();
                        const RANDOM_VALUE: u32 = 0x1337;

                        let displacement = instruction.memory_displacement64();
                        instruction.set_memory_displacement64(displacement + RANDOM_VALUE as u64);
                        result.push(*instruction);

                        let mut pushf_instr = Instruction::with(Code::Pushfq);
                        pushf_instr.set_ip(instruction.ip() + 1);
                        result.push(pushf_instr);

                        let mut sub_instr =
                            Instruction::with2(Code::Sub_rm64_imm32, dest_reg, RANDOM_VALUE)
                                .unwrap();
                        sub_instr.set_ip(instruction.ip() + 2);
                        result.push(sub_instr);

                        let mut popfq_instr = Instruction::with(Code::Popfq);
                        popfq_instr.set_ip(instruction.ip() + 3);
                        result.push(popfq_instr);
                    } else {
                        result.push(*instruction);
                        skipped_instructions += 1;
                    }
                }
                _ => {
                    result.push(*instruction);
                    skipped_instructions += 1;
                }
            }
        }

        function.instructions = result;

        let total_mutations =
            mov_reg_reg_mutations + mov_reg_mem_mutations + mov_mem_reg_mutations + lea_mutations;
        debug!(
            "Mutation pass completed on function {}: {} total mutations ({} mov_reg_reg, {} mov_reg_mem, {} mov_mem_reg, {} lea) and {} skipped instructions",
            function.name,
            total_mutations,
            mov_reg_reg_mutations,
            mov_reg_mem_mutations,
            mov_mem_reg_mutations,
            lea_mutations,
            skipped_instructions
        );

        Ok(())
    }

    fn enabled_by_default(&self) -> bool {
        true
    }
}
