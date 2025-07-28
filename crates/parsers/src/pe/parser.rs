use crate::pe::{PEContext, PEType};
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

        Ok(())
    }

    pub fn with_pe<T, F>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&PE) -> T,
    {
        let pe_borrow = self.pe.borrow();
        pe_borrow.as_ref().map(f)
    }

    fn get_pe_type(&self) -> PEType {
        let characteristics = self.with_pe(|pe| pe.header.coff_header.characteristics);
        if let Some(characteristics) = characteristics {
            if characteristics & goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE == goblin::pe::characteristic::IMAGE_FILE_EXECUTABLE_IMAGE {
                return PEType::EXE;
            } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_DLL == goblin::pe::characteristic::IMAGE_FILE_DLL {
                return PEType::DLL;
            } else if characteristics & goblin::pe::characteristic::IMAGE_FILE_SYSTEM == goblin::pe::characteristic::IMAGE_FILE_SYSTEM {
                return PEType::SYS;
            }
        }
        PEType::UNKNOWN
    }

    fn get_pe_machine(&self) -> u16 {
        let machine = self.with_pe(|pe| pe.header.coff_header.machine);
        if let Some(machine) = machine {
            machine
        } else {
            goblin::pe::header::COFF_MACHINE_UNKNOWN
        }
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