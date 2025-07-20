use crate::binary::pe::PeFile;
use anyhow::Result;
use tracing::error;
use tracing::info;
use crate::binary::SectionOperations;

pub struct FunctionDiscovery {
    pe_file: PeFile,
    merged_sections: Vec<u8>,
}

impl FunctionDiscovery {
    pub fn new(pe_file: PeFile) -> Result<Self> {
        if !pe_file.is_loaded() {
            error!("PE file not loaded");
            return Err(anyhow::anyhow!("PE file not loaded"));
        }
        Ok(Self { pe_file, merged_sections: Vec::new() })
    }

    pub fn run(&mut self) {
        let sections = self.pe_file.get_code_sections().unwrap();
        info!("Found {} code sections", sections.len());

        self.merge_sections();
        info!("Merged sections: {:x}", self.merged_sections.len());

        let entry_point = self.pe_file.get_entry_point().unwrap();
        info!("Entry point: {:x}", entry_point);


    }

    fn merge_sections(&mut self) {
        let sections = self.pe_file.get_code_sections().unwrap();
        for section in sections {
            let rva = section.0;
            let size = section.1;
            let data = self.pe_file.read(rva, size).unwrap();
            self.merged_sections.extend_from_slice(&data);
        }
    }

    fn recursive_function_discovery(&self) {
     
    }
}