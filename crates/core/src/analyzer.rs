use crate::{CoreContext, function::RuntimeFunction};
use common::info;
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;
use std::cell::RefCell;

pub struct AnalyzerContext<'a> {
    pub pe_context: &'a RefCell<PEContext>,
    pub pdb_context: &'a RefCell<PDBContext>,
}

impl<'a> AnalyzerContext<'a> {
    pub fn new(core_context: &'a CoreContext) -> Self {
        Self {
            pe_context: &core_context.pe_context,
            pdb_context: &core_context.pdb_context,
        }
    }

    pub fn analyze(&mut self) -> Result<Vec<RuntimeFunction>, String> {
        let pdb_functions = match self.pdb_context.borrow().get_functions() {
            Ok(functions) => functions,
            Err(e) => {
                return Err(e.to_string());
            }
        };

        let pdb_functions = pdb_functions
            .iter()
            .filter(|f| f.size > 5)
            .collect::<Vec<_>>();
        let mut runtime_functions = Vec::with_capacity(pdb_functions.len());

        for pdb_function in pdb_functions {
            let function_name = pdb_function.name.clone();
            if function_name != "main" {
                continue;
            }

            let function_rva = pdb_function.rva;
            let mut runtime_function = RuntimeFunction::new(function_name, function_rva, pdb_function.size);
            match runtime_function.decode(&self.pe_context.borrow()) {
                Ok(_) => runtime_functions.push(runtime_function),
                Err(e) => {
                    info!(
                        "Failed to analyze function {:#x} {}: {}",
                        function_rva, pdb_function.name, e
                    );
                }
            }
        }

        Ok(runtime_functions)
    }
}
