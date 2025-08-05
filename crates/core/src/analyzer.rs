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

        let pdb_functions = self.pdb_context.borrow().get_functions()
            .map_err(|e| {
                error!("Failed to retrieve functions from PDB: {}", e);
                e.to_string()
            })?;

        let total_functions = pdb_functions.len();
        let size_filtered_functions: Vec<_> = pdb_functions.iter().filter(|f| f.size > 5).collect();
        let filtered_out_count = total_functions - size_filtered_functions.len();

        info!("Retrieved {} functions from PDB, filtered out {} due to size (≤5 bytes)", 
              total_functions, filtered_out_count);

        let mut successful_decodes = 0;
        let mut failed_decodes = 0;

        let mut obfuscator_functions: Vec<ObfuscatorFunction> = size_filtered_functions
            .iter()
            .filter_map(|pdb_function| {
                let mut obfuscator_function = ObfuscatorFunction::new(pdb_function);
                match obfuscator_function.decode(&self.pe_context.borrow()) {
                    Ok(_) => {
                        successful_decodes += 1;
                        debug!("Successfully decoded function {} at RVA {:#x}", 
                               pdb_function.name, pdb_function.rva);
                        Some(obfuscator_function)
                    }
                    Err(e) => {
                        failed_decodes += 1;
                        error!("Failed to analyze function {:#x} {}: {}", 
                               pdb_function.rva, pdb_function.name, e);
                        None
                    }
                }
            })
            .collect();

        info!("Function decoding: {} successful, {} failed", successful_decodes, failed_decodes);

        if obfuscator_functions.is_empty() {
            warn!("No functions remained after decoding");
            return Err("No functions to analyze".to_string());
        }

        obfuscator_functions.iter_mut().for_each(|f| f.capture_original_state());

        let exception_functions = self.pe_context.borrow().get_exception_functions()?;
        let before_unwind_filter = obfuscator_functions.len();
        
        // Remove functions that have unwind info
        obfuscator_functions.retain(|f| {
            !exception_functions.iter().any(|ef| ef.begin_address == f.rva)
        });
        
        let unwind_filtered_count = before_unwind_filter - obfuscator_functions.len();

        if obfuscator_functions.is_empty() {
            warn!("No functions remained after filtering out unwind info");
            return Err("No functions to analyze".to_string());
        }

        info!("Analysis completed: {} functions (filtered out {} with unwind info)", 
              obfuscator_functions.len(), unwind_filtered_count);
        Ok(obfuscator_functions)
    }
}
