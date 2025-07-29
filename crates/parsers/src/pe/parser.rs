use crate::pe::{PEContext, PEType};
use goblin::pe::PE;

impl PEContext {
    pub fn new(pe_data: Vec<u8>) -> Self {
        Self { pe_data }
    }

    fn parse(&self) -> Result<PE, String> {
        let leaked_data: &'static [u8] = Box::leak(self.pe_data.clone().into_boxed_slice());
        Ok(PE::parse(leaked_data).map_err(|e| e.to_string())?)
    }

    fn get_pe_type(&self) -> PEType {
        let pe = self.parse().unwrap();
        let characteristics = pe.header.coff_header.characteristics;
        if characteristics & goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE
            == goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE
        {
            return PEType::EXE;
        } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_DLL
            == goblin::pe::characteristic::IMAGE_FILE_DLL
        {
            return PEType::DLL;
        } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_SYSTEM
            == goblin::pe::characteristic::IMAGE_FILE_SYSTEM
        {
            return PEType::SYS;
        }
        PEType::UNKNOWN
    }

    fn get_pe_machine(&self) -> u16 {
        let pe = self.parse().unwrap();
        pe.header.coff_header.machine
    }

    pub fn is_supported(&self) -> bool {
        let pe_type = self.get_pe_type();
        let pe_machine = self.get_pe_machine();

        if pe_machine != goblin::pe::header::COFF_MACHINE_X86_64 {
            return false;
        }

        matches!(pe_type, PEType::EXE)
    }
}
