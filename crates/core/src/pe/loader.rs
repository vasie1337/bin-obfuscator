use crate::pe::PEContext;

use goblin::pe::PE;
use std::cell::RefCell;

impl PEContext {
    pub fn new(pe_data: Vec<u8>) -> Self {
        Self {
            pe_data,
            pe: RefCell::new(None),
        }
    }

    pub fn load(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.pe.borrow().is_some() {
            return Ok(());
        }

        let leaked_data: &'static [u8] = Box::leak(self.pe_data.clone().into_boxed_slice());
        let pe = PE::parse(leaked_data)?;
        
        *self.pe.borrow_mut() = Some(pe);
        
        Ok(())
    }
}