use iced_x86::{code_asm::*, Instruction, BlockEncoder, BlockEncoderOptions, InstructionBlock};
use anyhow::{Result, anyhow};
use crate::types::cfg::ControlFlowGraph;

pub struct CodeGenerator {
    assembler: CodeAssembler,
}

impl CodeGenerator {
    pub fn new(bitness: u32) -> Result<Self> {
        let assembler = CodeAssembler::new(bitness)
            .map_err(|e| anyhow!("Failed to create CodeAssembler: {}", e))?;
        
        Ok(Self { assembler })
    }

    pub fn add_nop(&mut self) -> Result<()> {
        self.assembler.nop()
            .map_err(|e| anyhow!("Failed to add NOP: {}", e))?;
        Ok(())
    }

    pub fn add_mov_reg_reg(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.mov(dst, src)
            .map_err(|e| anyhow!("Failed to add MOV: {}", e))?;
        Ok(())
    }

    pub fn add_mov_reg_imm(&mut self, dst: AsmRegister64, imm: u64) -> Result<()> {
        self.assembler.mov(dst, imm)
            .map_err(|e| anyhow!("Failed to add MOV: {}", e))?;
        Ok(())
    }

    pub fn add_push(&mut self, reg: AsmRegister64) -> Result<()> {
        self.assembler.push(reg)
            .map_err(|e| anyhow!("Failed to add PUSH: {}", e))?;
        Ok(())
    }

    pub fn add_pop(&mut self, reg: AsmRegister64) -> Result<()> {
        self.assembler.pop(reg)
            .map_err(|e| anyhow!("Failed to add POP: {}", e))?;
        Ok(())
    }

    pub fn add_xor(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.xor(dst, src)
            .map_err(|e| anyhow!("Failed to add XOR: {}", e))?;
        Ok(())
    }

    pub fn add_or(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.or(dst, src)
            .map_err(|e| anyhow!("Failed to add OR: {}", e))?;
        Ok(())
    }

    pub fn add_add(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.add(dst, src)
            .map_err(|e| anyhow!("Failed to add ADD: {}", e))?;
        Ok(())
    }

    pub fn add_add_imm(&mut self, dst: AsmRegister64, imm: i32) -> Result<()> {
        self.assembler.add(dst, imm)
            .map_err(|e| anyhow!("Failed to add ADD immediate: {}", e))?;
        Ok(())
    }

    pub fn add_sub(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.sub(dst, src)
            .map_err(|e| anyhow!("Failed to add SUB: {}", e))?;
        Ok(())
    }

    pub fn create_label(&mut self) -> CodeLabel {
        self.assembler.create_label()
    }

    pub fn set_label(&mut self, label: &mut CodeLabel) -> Result<()> {
        self.assembler.set_label(label)
            .map_err(|e| anyhow!("Failed to set label: {}", e))?;
        Ok(())
    }

    pub fn add_jmp(&mut self, label: CodeLabel) -> Result<()> {
        self.assembler.jmp(label)
            .map_err(|e| anyhow!("Failed to add JMP: {}", e))?;
        Ok(())
    }

    // Additional methods for opaque branches pass
    pub fn add_and(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.and(dst, src)
            .map_err(|e| anyhow!("Failed to add AND: {}", e))?;
        Ok(())
    }

    pub fn add_and_imm(&mut self, dst: AsmRegister64, imm: i32) -> Result<()> {
        self.assembler.and(dst, imm)
            .map_err(|e| anyhow!("Failed to add AND immediate: {}", e))?;
        Ok(())
    }

    pub fn add_cmp(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.cmp(dst, src)
            .map_err(|e| anyhow!("Failed to add CMP: {}", e))?;
        Ok(())
    }

    pub fn add_cmp_imm(&mut self, dst: AsmRegister64, imm: i32) -> Result<()> {
        self.assembler.cmp(dst, imm)
            .map_err(|e| anyhow!("Failed to add CMP immediate: {}", e))?;
        Ok(())
    }

    pub fn add_imul(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.imul_2(dst, src)
            .map_err(|e| anyhow!("Failed to add IMUL: {}", e))?;
        Ok(())
    }

    pub fn add_test(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.test(dst, src)
            .map_err(|e| anyhow!("Failed to add TEST: {}", e))?;
        Ok(())
    }

    pub fn add_test_imm(&mut self, dst: AsmRegister64, imm: i32) -> Result<()> {
        self.assembler.test(dst, imm)
            .map_err(|e| anyhow!("Failed to add TEST immediate: {}", e))?;
        Ok(())
    }

    pub fn add_je(&mut self, label: CodeLabel) -> Result<()> {
        self.assembler.je(label)
            .map_err(|e| anyhow!("Failed to add JE: {}", e))?;
        Ok(())
    }

    pub fn add_jne(&mut self, label: CodeLabel) -> Result<()> {
        self.assembler.jne(label)
            .map_err(|e| anyhow!("Failed to add JNE: {}", e))?;
        Ok(())
    }

    pub fn add_jge(&mut self, label: CodeLabel) -> Result<()> {
        self.assembler.jge(label)
            .map_err(|e| anyhow!("Failed to add JGE: {}", e))?;
        Ok(())
    }

    pub fn take_instructions(&mut self) -> Vec<Instruction> {
        self.assembler.take_instructions()
    }

    pub fn instructions(&self) -> &[Instruction] {
        self.assembler.instructions()
    }

    pub fn assemble(&mut self, rip: u64) -> Result<Vec<u8>> {
        self.assembler.assemble(rip)
            .map_err(|e| anyhow!("Failed to assemble: {}", e))
    }

    pub fn clear(&mut self) {
        let _ = self.assembler.take_instructions();
    }
}

pub fn lower(ir: &Vec<ControlFlowGraph>, new_section_rva: u64) -> Result<Vec<u8>> {
    let mut all_instructions = Vec::new();
    
    for cfg in ir {
        let mut block_ids: Vec<_> = cfg.blocks.keys().cloned().collect();
        block_ids.sort();
        
        for block_id in block_ids {
            if let Some(basic_block) = cfg.blocks.get(&block_id) {
                for instruction in &basic_block.instructions {
                    all_instructions.push(*instruction);
                }
            }
        }
    }
    
    if all_instructions.is_empty() {
        return Ok(Vec::new());
    }
    
    let instruction_block = InstructionBlock::new(&all_instructions, new_section_rva);
    
    let encoder_options = BlockEncoderOptions::NONE;
    
    match BlockEncoder::encode(64, instruction_block, encoder_options) {
        Ok(block_encoder_result) => Ok(block_encoder_result.code_buffer),
        Err(e) => Err(anyhow!("Failed to encode instructions: {}", e)),
    }
}