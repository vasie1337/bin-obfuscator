use super::Pass;
use crate::function::ObfuscatorFunction;
use common::debug;
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, MemoryOperand, OpKind};

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

pub fn get_instruction_bytes(bitness: u32, insts: Vec<Instruction>) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    for inst in insts.clone() {
        let mut encoder = Encoder::new(bitness);
        match encoder.encode(&inst, inst.ip()) {
            Ok(_) => buffer = [buffer, encoder.take_buffer()].concat(),
            Err(e) => return Err(e.to_string()),
        };
    }
    Ok(buffer)
}    

fn re_encode_instructions(
    insts: Vec<Instruction>,
    rip: u64,
) -> Result<Vec<Instruction>, String> {
    let mut result = Vec::new();
    let buffer = get_instruction_bytes(64, insts)?;
    let mut decoder = Decoder::new(64, &buffer, DecoderOptions::NONE);
    decoder.set_ip(rip);
    let mut inst = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut inst);
        result.push(inst);
    }
    Ok(result)
}

fn re_encode_instruction(
    inst: Instruction,
    rip: u64,
) -> Result<Instruction, String> {
    let instructions = vec![inst];
    let result = re_encode_instructions(instructions, rip)?;
    Ok(result[0])
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
        let mut skipped_instructions = 0;
        
        for instruction in function.instructions.iter() {
            let nop_instr = Instruction::with(Code::Nopw);
            let re_encoded_nop_instr = re_encode_instruction(nop_instr, instruction.instruction.ip())?;
            result.push(crate::function::InstructionWithId {
                id: function.next_id,
                instruction: re_encoded_nop_instr,
            });
            function.next_id += 1;

            // Preserve the original instruction's ID
            result.push(crate::function::InstructionWithId {
                id: instruction.id,
                instruction: instruction.instruction,
            });
        }

        function.instructions = result;

        debug!(
            "Mutation pass completed on function {}: {} mov_reg_reg mutations and {} skipped instructions",
            function.name,
            mov_reg_reg_mutations,
            skipped_instructions
        );

        Ok(())
    }

    fn enabled_by_default(&self) -> bool {
        true
    }
}