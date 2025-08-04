use crate::{CoreContext, function::RuntimeFunction};
use common::error;
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;
use std::cell::RefCell;
use std::rc::Rc;

pub struct AnalyzerContext {
    pub pe_context: Rc<RefCell<PEContext>>,
    pub pdb_context: Rc<RefCell<PDBContext>>,
}

impl AnalyzerContext {
    pub fn new(core_context: &CoreContext) -> Self {
        Self {
            pe_context: core_context.pe_context.clone(),
            pdb_context: core_context.pdb_context.clone(),
        }
    }

    pub fn analyze(&self) -> Result<Vec<RuntimeFunction>, String> {
        let pdb_functions = match self.pdb_context.borrow().get_functions() {
            Ok(functions) => functions,
            Err(e) => {
                return Err(e.to_string());
            }
        };

        let runtime_functions: Vec<RuntimeFunction> = pdb_functions
            .iter()
            .filter(|f| f.size > 5)
            //.filter(|f| f.rva == 0x1430)
            .filter_map(|pdb_function| {
                let mut runtime_function = RuntimeFunction::new(pdb_function);
                match runtime_function.decode(&self.pe_context.borrow()) {
                    Ok(_) => Some(runtime_function),
                    Err(e) => {
                        error!(
                            "Failed to analyze function {:#x} {}: {}",
                            pdb_function.rva, pdb_function.name, e
                        );
                        None
                    }
                }
            })
            .collect();

        Ok(runtime_functions)
    }
}
