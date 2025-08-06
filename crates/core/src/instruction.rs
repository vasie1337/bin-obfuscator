use iced_x86::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct InstructionContext {
    next_id: AtomicUsize,
}

impl Clone for InstructionContext {
    fn clone(&self) -> Self {
        Self {
            next_id: AtomicUsize::new(self.next_id.load(Ordering::SeqCst)),
        }
    }
}

impl InstructionContext {
    pub fn new() -> Self {
        Self {
            next_id: AtomicUsize::new(0),
        }
    }

    pub fn next_id(&self) -> usize {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn create_instruction(&self, instruction: Instruction) -> InstructionWithId {
        InstructionWithId::new(self.next_id(), instruction)
    }
}

#[derive(Clone)]
pub struct InstructionWithId {
    pub id: usize,
    pub instruction: Instruction,
}

impl InstructionWithId {
    pub fn new(id: usize, instruction: Instruction) -> Self {
        Self { id, instruction }
    }

    pub fn get_memory_operand(&self) -> MemoryOperand {
        let mem_base = self.instruction.memory_base();
        let mem_index = self.instruction.memory_index();
        let mem_scale = self.instruction.memory_index_scale();
        let mem_displ = self.instruction.memory_displacement64();
        let mem_displ_size = self.instruction.memory_displ_size();
        let is_broadcast = self.instruction.is_broadcast();
        let mem_seg = self.instruction.segment_prefix();
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

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(64);
        encoder.encode(&self.instruction, self.instruction.ip()).unwrap();
        encoder.take_buffer()
    }

    pub fn re_encode(&self, rip: u64) -> Result<Instruction, String> {
        let bytes = self.get_bytes();
        let mut decoder = Decoder::new(64, &bytes, DecoderOptions::NONE);
        decoder.set_ip(rip);
        let mut inst = Instruction::default();
        decoder.decode_out(&mut inst);
        Ok(inst)
    }
}