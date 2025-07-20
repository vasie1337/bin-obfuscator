use goblin::pe::PE;
use anyhow::{Result, Context, bail};

pub struct PeFile {
    buffer: Vec<u8>,
    loaded: bool,
    path: Option<String>,
}

#[allow(dead_code)]
impl PeFile {
    pub fn new() -> Self {
        Self { buffer: Vec::new(), loaded: false, path: None }
    }

    pub fn load(&mut self, path: &str) -> Result<()> {
        self.buffer = std::fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path))?;
        self.loaded = true;
        self.path = Some(path.to_string());
        Ok(())
    }

    pub fn save(&self, path: &str) -> Result<()> {
        std::fs::write(path, &self.buffer)
            .with_context(|| format!("Failed to write file: {}", path))?;
        Ok(())
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub fn resize_buffer(&mut self, new_size: usize) {
        self.buffer.resize(new_size, 0);
    }

    pub fn rva_to_offset(&self, rva: u64) -> Result<u64> {
        let pe = PE::parse(&self.buffer)
            .context("Failed to parse PE file")?;
            
        for section in &pe.sections {
            let section_start = section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;
            
            if rva >= section_start && rva < section_end {
                return Ok(rva - section_start + section.pointer_to_raw_data as u64);
            }
        }
        
        bail!("No section found for RVA: 0x{:x}", rva)
    }

    pub fn get_entry_point(&self) -> Result<u64> {
        let pe = PE::parse(&self.buffer)
            .context("Failed to parse PE file")?;
        Ok(pe.entry as u64)
    }

    pub fn read(&self, rva: u64, size: u64) -> Result<Vec<u8>> {
        let offset = self.rva_to_offset(rva)?;
        let end_offset = offset + size;
        
        if end_offset > self.buffer.len() as u64 {
            bail!("Read operation would exceed buffer bounds: offset=0x{:x}, size=0x{:x}, buffer_len=0x{:x}", 
                  offset, size, self.buffer.len());
        }
        
        Ok(self.buffer[offset as usize..end_offset as usize].to_vec())
    }

    pub fn write(&mut self, rva: u64, data: &[u8]) -> Result<()> {
        let offset = self.rva_to_offset(rva)?;
        let end_offset = offset + data.len() as u64;
        
        if end_offset > self.buffer.len() as u64 {
            bail!("Write operation would exceed buffer bounds: offset=0x{:x}, data_len=0x{:x}, buffer_len=0x{:x}", 
                  offset, data.len(), self.buffer.len());
        }
        
        self.buffer[offset as usize..end_offset as usize].copy_from_slice(data);
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}