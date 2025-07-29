use crate::pdb::{PDBContext, PDBFunction};
use symbolic::common::Name;
use symbolic::debuginfo::pdb::PdbObject;
use symbolic::demangle::{Demangle, DemangleOptions};

// TODO: Add error handling
impl PDBContext {
    pub fn new(pdb_data: Vec<u8>) -> Self {
        Self { pdb_data }
    }

    pub fn is_supported(&self) -> bool {
        true
    }

    pub fn get_functions(&self) -> Vec<PDBFunction> {
        self.parse().unwrap()
    }

    fn parse(&self) -> Result<Vec<PDBFunction>, String> {
        let pdb_object = PdbObject::parse(&self.pdb_data).map_err(|e| e.to_string())?;
        let symbol_map = pdb_object.symbol_map();

        let functions: Vec<PDBFunction> = symbol_map
            .iter()
            .filter_map(|sym| {
                sym.name().map(|name| PDBFunction {
                    name: self.demangle_name(name),
                    rva: sym.address as u32,
                    size: sym.size as u32,
                })
            })
            .collect();

        Ok(functions)
    }

    fn demangle_name(&self, name: &str) -> String {
        let name = Name::from(name);
        let demangled = name.try_demangle(DemangleOptions::complete());
        demangled.to_string()
    }
}
