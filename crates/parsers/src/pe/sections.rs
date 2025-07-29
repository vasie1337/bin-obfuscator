use crate::pe::PEContext;

impl PEContext {
    pub fn create_executable_section(&mut self, name: &str, bytes: &[u8]) -> Result<(u64, u32), String> {
        const EXECUTABLE_CHARACTERISTICS: u32 = 0x60000020; // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        self.create_section(name, bytes.len() as u32, EXECUTABLE_CHARACTERISTICS)
            .and_then(|(virtual_address, virtual_size)| {
                self.write_data_at_rva(virtual_address as u32, bytes)
                    .map(|_| (virtual_address, virtual_size))
            })
    }

    pub fn get_next_section_rva(&self) -> Result<u64, String> {
        let pe = self.parse()?;
        
        if pe.sections.is_empty() {
            return Err("PE file has no sections".to_string());
        }
        
        let section_alignment = pe.header
            .optional_header
            .ok_or("Missing optional header")?
            .windows_fields
            .section_alignment;
        
        let last_section = pe.sections.last().unwrap();
        let last_section_end = last_section.virtual_address + last_section.virtual_size;
        
        let next_rva = align_up(last_section_end as u64, section_alignment as u64);
        
        Ok(next_rva)
    }

    fn create_section(&mut self, name: &str, size: u32, characteristics: u32) -> Result<(u64, u32), String> {
        if name.len() > 8 {
            return Err("Section name cannot be longer than 8 characters".to_string());
        }

        let (section_alignment, file_alignment, last_section_info, num_sections, optional_header_size, nt_headers_offset) = {
            let pe = self.parse()?;
            
            if pe.sections.is_empty() {
                return Err("PE file has no sections".to_string());
            }

            let optional_header = pe.header
                .optional_header
                .ok_or("Missing optional header")?;
            
            let section_alignment = optional_header.windows_fields.section_alignment;
            let file_alignment = optional_header.windows_fields.file_alignment;
            
            let last_section = pe.sections.last().unwrap();
            let last_section_info = (
                last_section.virtual_address,
                last_section.virtual_size,
                last_section.pointer_to_raw_data,
                last_section.size_of_raw_data,
            );
            let num_sections = pe.sections.len();
            let optional_header_size = pe.header.coff_header.size_of_optional_header as usize;
            let nt_headers_offset = self.get_nt_headers_offset()?;
            
            (section_alignment, file_alignment, last_section_info, num_sections, optional_header_size, nt_headers_offset)
        };
        
        let (last_virtual_address, last_virtual_size, last_pointer_to_raw_data, last_size_of_raw_data) = last_section_info;
        
        let virtual_size = size;
        let virtual_address = align_up(
            (last_virtual_address + last_virtual_size) as u64, 
            section_alignment as u64
        ) as u32;
        
        let size_of_raw_data = align_up(size as u64, file_alignment as u64) as u32;
        let pointer_to_raw_data = align_up(
            (last_pointer_to_raw_data + last_size_of_raw_data) as u64,
            file_alignment as u64
        ) as u32;
        
        let new_image_size = align_up(
            (virtual_address + virtual_size) as u64,
            section_alignment as u64
        ) as u32;
        
        let new_buffer_size = pointer_to_raw_data + size_of_raw_data;
        if self.pe_data.len() < new_buffer_size as usize {
            self.pe_data.resize(new_buffer_size as usize, 0);
        }

        let section_headers_offset = nt_headers_offset + 4 + 20 + optional_header_size; // NT signature + COFF header + optional header
        let section_header_size = 40;
        
        let new_section_offset = section_headers_offset + num_sections * section_header_size;
        
        if new_section_offset + section_header_size > pointer_to_raw_data as usize {
            return Err("Not enough space for new section header".to_string());
        }

        let section_header = self.create_section_header(
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            characteristics,
        );
        
        // Write the section header
        self.pe_data[new_section_offset..new_section_offset + section_header_size]
            .copy_from_slice(&section_header);

        // Update number of sections in COFF header
        let num_sections_offset = nt_headers_offset + 4 + 2; // NT signature + machine field
        let new_num_sections = (num_sections + 1) as u16;
        self.pe_data[num_sections_offset..num_sections_offset + 2]
            .copy_from_slice(&new_num_sections.to_le_bytes());

        // Update size of image in optional header
        let size_of_image_offset = nt_headers_offset + 4 + 20 + 56; // NT + COFF + offset to SizeOfImage
        self.pe_data[size_of_image_offset..size_of_image_offset + 4]
            .copy_from_slice(&new_image_size.to_le_bytes());
        
        Ok((virtual_address as u64, virtual_size))
    }

    fn get_nt_headers_offset(&self) -> Result<usize, String> {
        if self.pe_data.len() < 64 {
            return Err("PE file too small to contain DOS header".to_string());
        }
        
        let nt_headers_offset = u32::from_le_bytes([
            self.pe_data[60], self.pe_data[61], self.pe_data[62], self.pe_data[63]
        ]) as usize;
        
        if nt_headers_offset >= self.pe_data.len() {
            return Err("Invalid NT headers offset".to_string());
        }
        
        Ok(nt_headers_offset)
    }

    fn create_section_header(
        &self,
        name: &str,
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        characteristics: u32,
    ) -> [u8; 40] {
        let mut section_header = [0u8; 40];
        
        // Section name (8 bytes)
        let name_bytes = name.as_bytes();
        section_header[..name_bytes.len()].copy_from_slice(name_bytes);
        
        // Virtual size (4 bytes at offset 8)
        section_header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
        
        // Virtual address (4 bytes at offset 12)
        section_header[12..16].copy_from_slice(&virtual_address.to_le_bytes());
        
        // Size of raw data (4 bytes at offset 16)
        section_header[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());
        
        // Pointer to raw data (4 bytes at offset 20)
        section_header[20..24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
        
        // Pointer to relocations (4 bytes at offset 24) - unused, set to 0
        section_header[24..28].copy_from_slice(&0u32.to_le_bytes());
        
        // Pointer to line numbers (4 bytes at offset 28) - unused, set to 0  
        section_header[28..32].copy_from_slice(&0u32.to_le_bytes());
        
        // Number of relocations (2 bytes at offset 32) - unused, set to 0
        section_header[32..34].copy_from_slice(&0u16.to_le_bytes());
        
        // Number of line numbers (2 bytes at offset 34) - unused, set to 0
        section_header[34..36].copy_from_slice(&0u16.to_le_bytes());
        
        // Characteristics (4 bytes at offset 36)
        section_header[36..40].copy_from_slice(&characteristics.to_le_bytes());
        
        section_header
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}