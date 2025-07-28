use crate::pe::PEContext;

use goblin::pe::PE;
use symbolic::common::{Language, Name, NameMangling};
use symbolic::demangle::{Demangle, DemangleOptions};

impl PEContext {
    pub fn load(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let pe_data = data.to_vec();
        let leaked_data: &'static [u8] = Box::leak(pe_data.clone().into_boxed_slice());
        let pe = PE::parse(leaked_data)?;
        
        let ctx = Self {
            pe_data,
            pe,
        };
        
        Ok(ctx)
    }

    pub fn loop_imports(&self) {
        for import in self.pe.imports.iter() {
            let name = Name::new(import.name.as_ref(), NameMangling::Mangled, Language::Cpp);
            let demangled = name.try_demangle(DemangleOptions::name_only());
            println!("Import: {}", demangled);
        }
    }
}