use iced_x86::{code_asm::*, Instruction};
use anyhow::{Result, anyhow};

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

    pub fn add_add(&mut self, dst: AsmRegister64, src: AsmRegister64) -> Result<()> {
        self.assembler.add(dst, src)
            .map_err(|e| anyhow!("Failed to add ADD: {}", e))?;
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
