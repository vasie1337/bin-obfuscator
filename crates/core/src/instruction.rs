use iced_x86::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct InstructionContext {
    next_id: AtomicUsize,
}

impl Clone for InstructionContext {
    fn clone(&self) -> Self {
        Self {
            next_id: AtomicUsize::new(self.next_id.load(Ordering::Relaxed)),
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
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn create_instruction(&self, instruction: Instruction) -> InstructionWithId {
        InstructionWithId::new(self.next_id(), instruction)
    }
}

impl Default for InstructionContext {
    fn default() -> Self {
        Self::new()
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

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn set_id(&mut self, id: usize) {
        self.id = id;
    }

    pub fn get_memory_operand(&self) -> MemoryOperand {
        let instr = &self.instruction;
        MemoryOperand::new(
            instr.memory_base(),
            instr.memory_index(),
            instr.memory_index_scale(),
            instr.memory_displacement64() as i64,
            instr.memory_displ_size(),
            instr.is_broadcast(),
            instr.segment_prefix(),
        )
    }

    pub fn get_bytes(&self) -> Result<Vec<u8>, String> {
        let mut encoder = Encoder::new(64);
        encoder
            .encode(&self.instruction, self.instruction.ip())
            .map_err(|e| format!("Encoding failed: {}", e))?;
        Ok(encoder.take_buffer())
    }

    pub fn re_encode(&self, rip: u64) -> Result<Instruction, String> {
        let bytes = self.get_bytes()?;
        let mut decoder = Decoder::new(64, &bytes, DecoderOptions::NONE);
        decoder.set_ip(rip);
        let mut inst = Instruction::default();
        decoder.decode_out(&mut inst);
        Ok(inst)
    }
}

impl std::fmt::Debug for InstructionWithId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstructionWithId {{ id: {}, instruction: {:?} }}", self.id, self.instruction)
    }
}

impl std::fmt::Display for InstructionWithId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstructionWithId {{ id: {}, instruction: {:?} }}", self.id, self.instruction)
    }
}
