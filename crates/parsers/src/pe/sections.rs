use crate::pe::PEContext;

impl PEContext {
    pub fn create_executable_section(&mut self, name: &str, bytes: &[u8]) -> Result<(u64, u32), String> {
        let characteristics = 0x60000020;
        self.create_section(name, bytes.len() as u32, characteristics)
        .and_then(|(virtual_address, virtual_size)| {
            self.write_data_at_rva(virtual_address as u32, bytes)
            .map(|_| (virtual_address, virtual_size))
        })
    }

    pub fn get_next_section_rva(&self) -> Result<u64, String> {
        let pe = self.parse().unwrap();
        
        if pe.sections.is_empty() {
            return Err("PE file has no sections".to_string());
        }
        
        let nt_headers_offset = u32::from_le_bytes([
            self.pe_data[60], self.pe_data[61], self.pe_data[62], self.pe_data[63]
        ]) as usize;
        
        let optional_header_offset = nt_headers_offset + 4 + 20;
        let section_alignment = u32::from_le_bytes([
            self.pe_data[optional_header_offset + 32],
            self.pe_data[optional_header_offset + 33], 
            self.pe_data[optional_header_offset + 34],
            self.pe_data[optional_header_offset + 35],
        ]);
        
        let last_section = &pe.sections[pe.sections.len() - 1];
        let last_section_rva = last_section.virtual_address as u64;
        let last_section_size = last_section.virtual_size as u64;
        
        let align = |value: u32, alignment: u32| -> u32 {
            (value + alignment - 1) & !(alignment - 1)
        };
        
        let next_rva = align(
            (last_section_rva + last_section_size) as u32,
            section_alignment
        ) as u64;
        
        Ok(next_rva)
    }

    fn create_section(&mut self, name: &str, size: u32, characteristics: u32) -> Result<(u64, u32), String> {
        if name.len() > 8 {
            return Err("Section name cannot be longer than 8 characters".to_string());
        }

        let (nt_headers_offset, last_section_data, section_alignment, file_alignment) = {
            let pe = self.parse().unwrap();

            let nt_headers_offset = u32::from_le_bytes([
                self.pe_data[60], self.pe_data[61], self.pe_data[62], self.pe_data[63]
            ]) as usize;

            if pe.sections.is_empty() {
                return Err("PE file has no sections".to_string());
            }
            
            let last_section = &pe.sections[pe.sections.len() - 1];
            let last_section_data = (
                last_section.virtual_address,
                last_section.virtual_size,
                last_section.pointer_to_raw_data,
                last_section.size_of_raw_data,
                pe.sections.len()
            );
            
            let optional_header_offset = nt_headers_offset + 4 + 20;
            let section_alignment = u32::from_le_bytes([
                self.pe_data[optional_header_offset + 32],
                self.pe_data[optional_header_offset + 33], 
                self.pe_data[optional_header_offset + 34],
                self.pe_data[optional_header_offset + 35],
            ]);
            let file_alignment = u32::from_le_bytes([
                self.pe_data[optional_header_offset + 36],
                self.pe_data[optional_header_offset + 37],
                self.pe_data[optional_header_offset + 38], 
                self.pe_data[optional_header_offset + 39],
            ]);

            (nt_headers_offset, last_section_data, section_alignment, file_alignment)
        };

        let section_headers_offset = nt_headers_offset + 4 + 20 + u16::from_le_bytes([
            self.pe_data[nt_headers_offset + 4 + 16],
            self.pe_data[nt_headers_offset + 4 + 17],
        ]) as usize;
        let section_header_size = 40;
        
        let (last_virtual_address, last_virtual_size, last_pointer_to_raw_data, last_size_of_raw_data, num_sections) = last_section_data;
        
        let align = |value: u32, alignment: u32| -> u32 {
            (value + alignment - 1) & !(alignment - 1)
        };
        
        let virtual_size = size;
        let virtual_address = align(
            last_virtual_address + last_virtual_size, 
            section_alignment
        );
        let size_of_raw_data = align(size, file_alignment);
        let pointer_to_raw_data = align(
            last_pointer_to_raw_data + last_size_of_raw_data,
            file_alignment
        );
        
        let new_image_size = align(
            virtual_address + virtual_size,
            section_alignment
        );
        
        let new_buffer_size = pointer_to_raw_data + size_of_raw_data;
        if self.pe_data.len() < new_buffer_size as usize {
            self.pe_data.resize(new_buffer_size as usize, 0);
        }

        let new_section_offset = section_headers_offset + num_sections * section_header_size;
        
        if new_section_offset + section_header_size > pointer_to_raw_data as usize {
            return Err("Not enough space for new section header".to_string());
        }

        let mut section_header = [0u8; 40];
        
        let name_bytes = name.as_bytes();
        section_header[..name_bytes.len()].copy_from_slice(name_bytes);
        
        section_header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
        section_header[12..16].copy_from_slice(&virtual_address.to_le_bytes());
        section_header[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());
        section_header[20..24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
        section_header[24..28].copy_from_slice(&0u32.to_le_bytes());
        section_header[28..32].copy_from_slice(&0u32.to_le_bytes());
        section_header[32..34].copy_from_slice(&0u16.to_le_bytes());
        section_header[34..36].copy_from_slice(&0u16.to_le_bytes());
        section_header[36..40].copy_from_slice(&characteristics.to_le_bytes());
        
        self.pe_data[new_section_offset..new_section_offset + section_header_size]
            .copy_from_slice(&section_header);

        let num_sections_offset = nt_headers_offset + 4 + 2;
        let new_num_sections = (num_sections + 1) as u16;
        self.pe_data[num_sections_offset..num_sections_offset + 2]
            .copy_from_slice(&new_num_sections.to_le_bytes());

        let size_of_image_offset = nt_headers_offset + 4 + 20 + 56;
        self.pe_data[size_of_image_offset..size_of_image_offset + 4]
            .copy_from_slice(&new_image_size.to_le_bytes());
        
        Ok((virtual_address as u64, virtual_size as u32))
    }
}