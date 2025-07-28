use crate::pe::{PEContext, PEType};
use common::info;
use goblin::pe::PE;
use std::cell::RefCell;

impl PEContext {
    pub fn new(pe_data: Vec<u8>) -> Self {
        Self {
            pe_data,
            pe: RefCell::new(None),
        }
    }

    pub fn parse(&self) -> Result<(), String> {
        if self.pe.borrow().is_some() {
            return Ok(());
        }

        let leaked_data: &'static [u8] = Box::leak(self.pe_data.clone().into_boxed_slice());
        let pe = PE::parse(leaked_data).map_err(|e| e.to_string())?;
        
        *self.pe.borrow_mut() = Some(pe);

        if !self.is_supported() {
            return Err("PE is not supported".to_string());
        }

        info!("Successfully parsed PE with type: {:?}", self.get_pe_type());

        Ok(())
    }

    fn get_pe_type(&self) -> PEType {
        let pe_borrow = self.pe.borrow();
        let pe = pe_borrow.as_ref().unwrap();
        let characteristics = pe.header.coff_header.characteristics;

        if characteristics & goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE == goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE {
            return PEType::EXE;
        } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_DLL == goblin::pe::characteristic::IMAGE_FILE_DLL {
            return PEType::DLL;
        } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_SYSTEM == goblin::pe::characteristic::IMAGE_FILE_SYSTEM {
            return PEType::SYS;
        } else {
            return PEType::UNKNOWN;
        }
    }

    fn get_pe_machine(&self) -> u16 {
        let pe_borrow = self.pe.borrow();
        let pe = pe_borrow.as_ref().unwrap();
        pe.header.coff_header.machine
    }

    fn is_supported(&self) -> bool {
        let pe_type = self.get_pe_type();
        let pe_machine = self.get_pe_machine();

        if pe_machine != goblin::pe::header::COFF_MACHINE_X86_64 {
            return false;
        }

        match pe_type {
            PEType::EXE => true,
            _ => false,
        }
    }
}