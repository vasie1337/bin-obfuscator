use crate::pdb::PDBContext;
use crate::pe::PEContext;
use crate::{CoreContext, function::ObfuscatorFunction};
use common::{debug, error, info, warn};
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

    pub fn analyze(&self) -> Result<Vec<ObfuscatorFunction>, String> {
        debug!("Starting function analysis from PDB context");

        let pdb_functions = match self.pdb_context.borrow().get_functions() {
            Ok(functions) => {
                info!("Retrieved {} functions from PDB", functions.len());
                functions
            }
            Err(e) => {
                error!("Failed to retrieve functions from PDB: {}", e);
                return Err(e.to_string());
            }
        };

        debug!("Filtering functions by size (> 5 bytes)");
        let filtered_functions: Vec<_> = pdb_functions.iter().filter(|f| f.size > 5).collect();

        info!(
            "Filtered to {} functions after size filtering",
            filtered_functions.len()
        );

        if filtered_functions.is_empty() {
            warn!("No functions found after filtering");
            return Err("No functions to analyze".to_string());
        }

        debug!("Starting function decoding process");
        let mut successful_decodes = 0;
        let mut failed_decodes = 0;

        let mut obfuscator_functions: Vec<ObfuscatorFunction> = filtered_functions
            .iter()
            .filter_map(|pdb_function| {
                let mut obfuscator_function = ObfuscatorFunction::new(pdb_function);
                match obfuscator_function.decode(&self.pe_context.borrow()) {
                    Ok(_) => {
                        successful_decodes += 1;
                        debug!(
                            "Successfully decoded function {} at RVA {:#x} with {} instructions",
                            pdb_function.name,
                            pdb_function.rva,
                            obfuscator_function.instructions.len()
                        );
                        Some(obfuscator_function)
                    }
                    Err(e) => {
                        failed_decodes += 1;
                        error!(
                            "Failed to analyze function {:#x} {}: {}",
                            pdb_function.rva, pdb_function.name, e
                        );
                        None
                    }
                }
            })
            .collect();

        info!(
            "Function decoding completed: {} successful, {} failed",
            successful_decodes, failed_decodes
        );

        if obfuscator_functions.len() == 0 {
            warn!("No functions remained after decoding");
            return Err("No functions to analyze".to_string());
        }

        debug!(
            "Capturing original state for {} functions",
            obfuscator_functions.len()
        );
        obfuscator_functions
            .iter_mut()
            .for_each(|f| f.capture_original_state());

        let pe_context_borrow = self.pe_context.borrow();
        let exception_functions = pe_context_borrow.get_exception_functions()?;

        for obfuscator_function in &mut obfuscator_functions {
            let function = exception_functions
                .iter()
                .find(|f| f.begin_address == obfuscator_function.rva);
            if let Some(func) = function {
                obfuscator_function.unwind_info_address = Some(func.unwind_info_address);
                debug!("Found unwind function for {}", obfuscator_function.name);
            }
        }

        info!(
            "Analysis completed successfully with {} functions",
            obfuscator_functions.len()
        );
        Ok(obfuscator_functions)
    }
}
