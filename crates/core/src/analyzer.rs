use crate::pdb::{PDBContext, PDBFunction};
use crate::pe::PEContext;
use crate::{
    CoreContext,
    function::{Decodable, ObfuscatorFunction, StateManaged},
};
use common::info;
use std::cell::RefCell;
use std::rc::Rc;

pub struct AnalyzerContext {
    pe_context: Rc<RefCell<PEContext>>,
    pdb_context: Rc<RefCell<PDBContext>>,
}

impl AnalyzerContext {
    pub fn new(core_context: &CoreContext) -> Self {
        Self {
            pe_context: core_context.pe_context.clone(),
            pdb_context: core_context.pdb_context.clone(),
        }
    }

    fn filter_by_size(&self, pdb_functions: &[PDBFunction]) -> Vec<PDBFunction> {
        let total = pdb_functions.len();
        let size_filtered: Vec<PDBFunction> = pdb_functions
            .iter()
            .filter(|f| f.size > 5)
            .cloned()
            .collect();
        let filtered_count = total - size_filtered.len();
        info!(
            "Size filter: {} functions remaining (filtered out {} ≤5 bytes)",
            size_filtered.len(),
            filtered_count
        );
        size_filtered
    }

    fn decode_functions(&self, pdb_functions: Vec<PDBFunction>) -> Vec<ObfuscatorFunction> {
        let mut failed_decodes = 0;
        let functions: Vec<ObfuscatorFunction> = pdb_functions
            .iter()
            .filter_map(|f| {
                let mut func = ObfuscatorFunction::new(f);
                match func.decode(&self.pe_context.borrow()) {
                    Ok(_) => Some(func),
                    Err(_) => {
                        failed_decodes += 1;
                        None
                    }
                }
            })
            .collect();

        info!(
            "Decode: {} functions successfully decoded, {} failed",
            functions.len(),
            failed_decodes
        );
        functions
    }

    fn analyze_functions(&self, functions: &mut [ObfuscatorFunction]) -> Result<(), String> {
        for func in functions.iter_mut() {
            func.capture_original_state();
            func.build_branch_map();
        }
        Ok(())
    }

    fn filter_by_exception(
        &self,
        mut functions: Vec<ObfuscatorFunction>,
    ) -> Result<Vec<ObfuscatorFunction>, String> {
        let exception_functions = self.pe_context.borrow().get_exception_functions()?;
        let before = functions.len();
        functions.retain(|f| {
            !exception_functions
                .iter()
                .any(|ef| ef.begin_address == f.rva)
        });

        let filtered_count = before - functions.len();
        info!(
            "Exception filter: {} functions remaining (filtered out {} with unwind info)",
            functions.len(),
            filtered_count
        );
        Ok(functions)
    }

    pub fn analyze(&self) -> Result<Vec<ObfuscatorFunction>, String> {
        let pdb_functions = self
            .pdb_context
            .borrow()
            .get_functions()
            .map_err(|e| e.to_string())?;

        info!("Retrieved {} functions from PDB", pdb_functions.len());

        let size_filtered = self.filter_by_size(&pdb_functions);
        if size_filtered.is_empty() {
            return Err("No functions to analyze".to_string());
        }

        let decoded_functions = self.decode_functions(size_filtered);
        if decoded_functions.is_empty() {
            return Err("No functions to analyze".to_string());
        }

        let mut functions = self.filter_by_exception(decoded_functions)?;
        if functions.is_empty() {
            return Err("No functions to analyze".to_string());
        }

        // DEBUG: only main function
        //functions = functions.iter().filter(|f| f.name.contains("pre_c_initialization")).cloned().collect();

        self.analyze_functions(&mut functions)?;

        info!(
            "Analysis completed: {} functions ready for obfuscation",
            functions.len()
        );
        Ok(functions)
    }
}
