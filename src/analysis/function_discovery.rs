use crate::binary::pe::PeFile;
use anyhow::Result;
use tracing::error;
use tracing::info;
use crate::binary::SectionOperations;

pub struct FunctionDiscovery {
    pe_file: PeFile,
}

impl FunctionDiscovery {
    pub fn new(pe_file: PeFile) -> Result<Self> {
        if !pe_file.is_loaded() {
            error!("PE file not loaded");
            return Err(anyhow::anyhow!("PE file not loaded"));
        }
        Ok(Self { pe_file })
    }

    pub fn run(&self) {
        let sections = self.pe_file.get_code_sections().unwrap();
        info!("Found {} code sections", sections.len());

        for section in sections {
            let rva = section.0;
            let size = section.1;
            let data = self.pe_file.read(rva, size).unwrap();
            info!("Section RVA: 0x{:x}, Size: 0x{:x}", rva, size);
        }
    }
}