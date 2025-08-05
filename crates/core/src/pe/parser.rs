use crate::pe::{PEContext, PEType};
use goblin::pe::PE;

#[derive(Debug, Clone)]
pub struct UnwindFunction {
    pub begin_address: u32,
    pub end_address: u32,
}

impl PEContext {
    pub fn new(pe_data: Vec<u8>) -> Self {
        Self { pe_data }
    }

    pub fn parse(&self) -> Result<PE, String> {
        PE::parse(&self.pe_data).map_err(|e| e.to_string())
    }

    fn get_pe_type(&self) -> Result<PEType, String> {
        let pe = match self.parse() {
            Ok(pe) => pe,
            Err(e) => {
                return Err(e.to_string());
            }
        };
        let characteristics = pe.header.coff_header.characteristics;
        if characteristics & goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE
            == goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE
        {
            return Ok(PEType::EXE);
        } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_DLL
            == goblin::pe::characteristic::IMAGE_FILE_DLL
        {
            return Ok(PEType::DLL);
        } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_SYSTEM
            == goblin::pe::characteristic::IMAGE_FILE_SYSTEM
        {
            return Ok(PEType::SYS);
        }

        Err("Unsupported PE type".to_string())
    }

    fn get_pe_machine(&self) -> u16 {
        let pe = match self.parse() {
            Ok(pe) => pe,
            Err(_) => return 0,
        };
        pe.header.coff_header.machine
    }

    pub fn is_supported(&self) -> bool {
        let pe_type = match self.get_pe_type() {
            Ok(pe_type) => pe_type,
            Err(_) => return false,
        };

        let pe_machine = self.get_pe_machine();

        if pe_machine != goblin::pe::header::COFF_MACHINE_X86_64 {
            return false;
        }

        matches!(pe_type, PEType::EXE | PEType::DLL)
    }

    pub fn read_data(&self, offset: usize, size: usize) -> Result<Vec<u8>, String> {
        if offset + size > self.pe_data.len() {
            return Err("Read would exceed file bounds".to_string());
        }
        Ok(self.pe_data[offset..offset + size].to_vec())
    }

    pub fn write_data(&mut self, offset: usize, data: &[u8]) -> Result<(), String> {
        if offset + data.len() > self.pe_data.len() {
            return Err("Write would exceed file bounds".to_string());
        }
        self.pe_data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Result<usize, String> {
        let pe = self.parse()?;

        if rva
            < pe.header
                .optional_header
                .ok_or("Optional header not found".to_string())?
                .windows_fields
                .size_of_headers
        {
            return Ok(rva as usize);
        }

        for section in &pe.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Ok((section.pointer_to_raw_data + offset_in_section) as usize);
            }
        }

        Err(format!("RVA {rva:#x} not found in any section"))
    }

    pub fn file_offset_to_rva(&self, file_offset: usize) -> Result<u32, String> {
        let pe = self.parse()?;
        let file_offset = file_offset as u32;

        if file_offset
            < pe.header
                .optional_header
                .ok_or("Optional header not found".to_string())?
                .windows_fields
                .size_of_headers
        {
            return Ok(file_offset);
        }

        for section in &pe.sections {
            let section_file_start = section.pointer_to_raw_data;
            let section_file_end = section_file_start + section.size_of_raw_data;

            if file_offset >= section_file_start && file_offset < section_file_end {
                let offset_in_section = file_offset - section_file_start;
                return Ok(section.virtual_address + offset_in_section);
            }
        }

        Err(format!(
            "File offset {file_offset:#x} not found in any section"
        ))
    }

    pub fn read_data_at_rva(&self, rva: u32, size: usize) -> Result<Vec<u8>, String> {
        let file_offset = self.rva_to_file_offset(rva)?;
        self.read_data(file_offset, size)
    }

    pub fn write_data_at_rva(&mut self, rva: u32, data: &[u8]) -> Result<(), String> {
        let file_offset = self.rva_to_file_offset(rva)?;
        self.write_data(file_offset, data)
    }

    pub fn get_exception_functions(
        &self,
    ) -> Result<Vec<goblin::pe::exception::RuntimeFunction>, String> {
        let pe = self.parse()?;
        let exception_data = pe
            .exception_data
            .ok_or("Exception data not found")?;

        Ok(exception_data
            .functions()
            .filter_map(|f| f.as_ref().ok().cloned())
            .filter(|function| {
                exception_data
                    .get_unwind_info(*function, &pe.sections)
                    .map_or(false, |info| info.handler.is_some())
            })
            .collect())
    }
}
