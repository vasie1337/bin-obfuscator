use goblin::pe::PE;
use anyhow::{Result, Context, bail};
use tracing::{info, debug, warn, error};
use std::path::{Path, PathBuf};

use crate::binary::SectionOperations;
use crate::types::{ControlFlowGraph, Function};

pub struct PeFile {
    buffer: Vec<u8>,
    loaded: bool,
    path: Option<PathBuf>,
}

#[allow(dead_code)]
impl PeFile {
    pub fn new() -> Self {
        debug!("Creating new PeFile instance");
        Self { buffer: Vec::new(), loaded: false, path: None }
    }

    pub fn buffer(&self) -> &[u8] {
        debug!("Accessing buffer (size: {} bytes)", self.buffer.len());
        &self.buffer
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        debug!("Accessing mutable buffer (size: {} bytes)", self.buffer.len());
        &mut self.buffer
    }

    pub fn resize_buffer(&mut self, new_size: usize) {
        let old_size = self.buffer.len();
        debug!("Resizing buffer from {} to {} bytes", old_size, new_size);
        self.buffer.resize(new_size, 0);
        
        if new_size > old_size {
            debug!("Buffer grown by {} bytes", new_size - old_size);
        } else if new_size < old_size {
            debug!("Buffer shrunk by {} bytes", old_size - new_size);
        }
    }

    pub fn rva_to_offset(&self, rva: u64) -> Result<u64> {
        debug!("Converting RVA 0x{:x} to file offset", rva);
        
        let pe = PE::parse(&self.buffer)
            .context("Failed to parse PE file")?;
            
        for (i, section) in pe.sections.iter().enumerate() {
            let section_start = section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;
            
            debug!("Checking section {}: {} (0x{:x}-0x{:x})", 
                   i, 
                   String::from_utf8_lossy(&section.name),
                   section_start, 
                   section_end);
            
            if rva >= section_start && rva < section_end {
                let offset = rva - section_start + section.pointer_to_raw_data as u64;
                debug!("RVA 0x{:x} found in section {} -> offset 0x{:x}", 
                       rva, String::from_utf8_lossy(&section.name), offset);
                return Ok(offset);
            }
        }
        
        warn!("No section found for RVA: 0x{:x}", rva);
        bail!("No section found for RVA: 0x{:x}", rva)
    }

    pub fn get_entry_point(&self) -> Result<u64> {
        debug!("Retrieving entry point from PE header");
        
        let pe = PE::parse(&self.buffer)
            .context("Failed to parse PE file")?;
        
        let entry_point = pe.entry as u64;
        debug!("Entry point: 0x{:x}", entry_point);
        Ok(entry_point)
    }

    pub fn get_bitness(&self) -> Result<u32> {
        debug!("Retrieving bitness from PE header");
        
        let pe = PE::parse(&self.buffer)
            .context("Failed to parse PE file")?;
        
        let is_64 = pe.is_64;
        let bitness = if is_64 { 64 } else { 32 };
        debug!("Bitness: {}", bitness);
        Ok(bitness)
    }

    pub fn read(&self, rva: u64, size: u64) -> Result<Vec<u8>> {
        debug!("Reading {} bytes from RVA 0x{:x}", size, rva);
        
        let offset = self.rva_to_offset(rva)?;
        let end_offset = offset + size;
        
        debug!("Reading from file offset 0x{:x} to 0x{:x}", offset, end_offset);
        
        if end_offset > self.buffer.len() as u64 {
            error!("Read operation would exceed buffer bounds: offset=0x{:x}, size=0x{:x}, buffer_len=0x{:x}", 
                  offset, size, self.buffer.len());
            bail!("Read operation would exceed buffer bounds: offset=0x{:x}, size=0x{:x}, buffer_len=0x{:x}", 
                  offset, size, self.buffer.len());
        }
        
        let data = self.buffer[offset as usize..end_offset as usize].to_vec();
        debug!("Successfully read {} bytes", data.len());
        Ok(data)
    }

    pub fn write(&mut self, rva: u64, data: &[u8]) -> Result<()> {
        debug!("Writing {} bytes to RVA 0x{:x}", data.len(), rva);
        
        let offset = self.rva_to_offset(rva)?;
        let end_offset = offset + data.len() as u64;
        
        debug!("Writing to file offset 0x{:x} to 0x{:x}", offset, end_offset);
        
        if end_offset > self.buffer.len() as u64 {
            error!("Write operation would exceed buffer bounds: offset=0x{:x}, data_len=0x{:x}, buffer_len=0x{:x}", 
                  offset, data.len(), self.buffer.len());
            bail!("Write operation would exceed buffer bounds: offset=0x{:x}, data_len=0x{:x}, buffer_len=0x{:x}", 
                  offset, data.len(), self.buffer.len());
        }
        
        self.buffer[offset as usize..end_offset as usize].copy_from_slice(data);
        debug!("Successfully wrote {} bytes", data.len());
        Ok(())
    }

    pub fn patch_jmp(&mut self, rva: u64, dest_rva: u64) -> Result<()> {
        let relative_offset = (dest_rva as i64) - ((rva + 5) as i64);

        let rel32 = relative_offset as i32;

        let mut jmp_bytes = [0u8; 5];
        jmp_bytes[0] = 0xE9;
        jmp_bytes[1..].copy_from_slice(&rel32.to_le_bytes());

        self.write(rva, &jmp_bytes)?;

        debug!(
            "Patched JMP at 0x{:x} to 0x{:x} (rel_offset: 0x{:x})",
            rva, dest_rva, rel32
        );
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn get_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

pub fn load_from_disk(path: &Path) -> Result<PeFile> {
    info!("Loading PE file from: {}", path.display());
    
    let file_size = std::fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for file: {}", path.display()))?
        .len();
    debug!("File size: {} bytes", file_size);
    
    let buffer = std::fs::read(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    
    debug!("Successfully read {} bytes from file", buffer.len());
    
    match PE::parse(&buffer) {
        Ok(pe) => {
            debug!("PE file validation successful - entry point: 0x{:x}", pe.entry);
            debug!("Number of sections: {}", pe.sections.len());
            for (i, section) in pe.sections.iter().enumerate() {
                debug!("Section {}: {} (VA: 0x{:x}, size: 0x{:x})", 
                       i, 
                       String::from_utf8_lossy(&section.name),
                       section.virtual_address,
                       section.virtual_size);
            }
            info!("Loaded {} bit PE file", if pe.is_64 { "64" } else { "32" });
        }
        Err(e) => {
            error!("Invalid PE file format: {}", e);
            return Err(e.into());
        }
    }
    Ok(PeFile { buffer, loaded: true, path: Some(path.to_path_buf()) })
}

pub fn save_to_disk(pe_file: &PeFile, path: &Path) -> Result<()> {
    info!("Saving PE file to: {}", path.display());
    debug!("Buffer size to write: {} bytes", pe_file.buffer.len());
    
        std::fs::write(path, &pe_file.buffer)
        .with_context(|| format!("Failed to write file: {}", path.display()))?;
    
    info!("PE file saved successfully to: {}", path.display());
    Ok(())
}

pub fn patch_with_new_code(pe_file: &mut PeFile, new_code: &[u8]) -> Result<()> {
    let (new_section_rva, _) = pe_file.create_executable_section(".test", new_code.len() as u32)?;
    pe_file.write(new_section_rva as u64, new_code)?;
    Ok(())
}

pub fn fix_calls(pe_file: &mut PeFile, ir: &Vec<ControlFlowGraph>, obfuscated_ir: &Vec<ControlFlowGraph>) -> Result<()> {
    for (old_function, new_function) in ir.iter().zip(obfuscated_ir.iter()) {
        let old_function_entry = old_function.get_entry_rva();
        let new_function_entry = new_function.get_entry_rva();

        assert!(old_function_entry != new_function_entry, "Old and new function entries must be different");

        if let (Some(old_function_entry), Some(new_function_entry)) = (old_function_entry, new_function_entry) {
            pe_file.patch_jmp(old_function_entry, new_function_entry)?;
        }
    }
    Ok(())
}