use crate::pdb::PDBContext;
use crate::types::Function;

use symbolic::common::Name;
use symbolic::demangle::{Demangle, DemangleOptions};
use symbolic::debuginfo::pdb::PdbObject;
use std::cell::RefCell;

impl PDBContext {
    pub fn new(pdb_data: Vec<u8>) -> Self {
        Self { 
            pdb_data,
            functions: RefCell::new(None),
        }
    }

    pub fn parse(&self) -> Result<(), String> {
        let pdb_object = PdbObject::parse(&self.pdb_data).map_err(|e| e.to_string())?;
        let symbol_map = pdb_object.symbol_map();
        
        let functions: Vec<Function> = symbol_map.iter().filter_map(|sym| {
            sym.name().map(|name| Function {
                name: self.demangle_name(name),
                rva: sym.address as u32,
                size: sym.size as u32,
            })
        }).collect();
        
        *self.functions.borrow_mut() = Some(functions);
        Ok(())
    }

    fn demangle_name(&self, name: &str) -> String {
        let name = Name::from(name);
        let demangled = name.try_demangle(DemangleOptions::complete());
        demangled.to_string()
    }

    pub fn get_functions(&self) -> Result<Vec<Function>, String> {
        self.parse()?;
        Ok(self.functions.borrow().as_ref().unwrap().clone())
    }

    #[allow(dead_code)]
    pub fn get_function_by_rva(&self, rva: u32) -> Result<Option<Function>, String> {
        self.parse()?;
        let functions = self.functions.borrow();
        let functions = functions.as_ref().unwrap();
        
        Ok(functions.iter().find(|f| f.rva == rva).cloned())
    }

}