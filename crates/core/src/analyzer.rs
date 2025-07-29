use crate::function::RuntimeFunction;
use common::info;
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;

pub struct AnalyzerContext {
    pub pe_context: PEContext,
    pub pdb_context: PDBContext,
}

impl AnalyzerContext {
    pub fn new(pe_context: PEContext, pdb_context: PDBContext) -> Self {
        Self {
            pe_context,
            pdb_context,
        }
    }

    pub fn analyze(&mut self) -> Result<Vec<RuntimeFunction>, String> {
        let pdb_functions = self.pdb_context.get_functions();

        let mut runtime_functions = Vec::with_capacity(pdb_functions.len());

        for pdb_function in pdb_functions {
            let function_name = pdb_function.name.clone();
            if function_name != "main" && function_name != "__security_init_cookie" && function_name != "__security_check_cookie" {
                continue; // TODO: remove this - only for testing
            }
            let function_rva = pdb_function.rva;
            let mut runtime_function = RuntimeFunction::new(function_name, function_rva, pdb_function.size);
            match runtime_function.decode(&self.pe_context) {
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
