use crate::pdb::{PDBContext, PDBFunction};
use symbolic::common::Name;
use symbolic::debuginfo::pdb::PdbObject;
use symbolic::demangle::{Demangle, DemangleOptions};

impl PDBContext {
    pub fn new(pdb_data: Vec<u8>) -> Self {
        Self { pdb_data }
    }

    pub fn is_supported(&self) -> bool {
        true
    }

    pub fn get_functions(&self) -> Result<Vec<PDBFunction>, String> {
        match self.parse() {
            Ok(functions) => Ok(functions),
            Err(e) => Err(e.to_string()),
        }
    }

	fn parse(&self) -> Result<Vec<PDBFunction>, String> {
	    let pdb_object = PdbObject::parse(&self.pdb_data).map_err(|e| e.to_string())?;
	    let mut functions = Vec::new();
	    
	    if let Ok(session) = pdb_object.debug_session() {
	        for func_result in session.functions() {
	            if let Ok(func) = func_result {
	                functions.push(PDBFunction {
	                    name: self.demangle_name(&func.name.to_string()),
	                    rva: func.address as u32,
	                    size: func.size as u32,
	                });
	            }
	        }
	    }
	    
	    functions.sort_by_key(|f: &PDBFunction| f.rva);
	    
	    functions.dedup_by(|a, b| a.rva == b.rva);
	    
	    Ok(functions)
	}

    fn demangle_name(&self, name: &str) -> String {
        let name = Name::from(name);
        let demangled = name.try_demangle(DemangleOptions::complete());
        demangled.to_string()
    }
}
