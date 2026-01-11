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

    fn has_jump_table(&self, func: &ObfuscatorFunction) -> bool {
        use iced_x86::{Code, OpKind};
        
        // Check for indirect jump patterns that indicate jump tables
        for inst_with_id in &func.instructions {
            let inst = &inst_with_id.instruction;
            
            // Check for JMP with memory operand (typical jump table pattern)
            // e.g., jmp qword ptr [rax*8+offset]
            if matches!(inst.code(), Code::Jmp_rm64) {
                // If it's an indirect jump with a memory operand
                if inst.op0_kind() == OpKind::Memory {
                    return true;
                }
            }
        }
        
        false
    }

    fn filter_by_jump_tables(&self, mut functions: Vec<ObfuscatorFunction>) -> Vec<ObfuscatorFunction> {
        let before = functions.len();
        functions.retain(|f| !self.has_jump_table(f));
        
        let filtered_count = before - functions.len();
        if filtered_count > 0 {
            info!(
                "Jump table filter: {} functions remaining (filtered out {} with jump tables)",
                functions.len(),
                filtered_count
            );
        }
        functions
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

        functions = self.filter_by_jump_tables(functions);
        if functions.is_empty() {
            return Err("No functions to analyze".to_string());
        }

        // DEBUG: only 1 function
        //functions = functions.iter().filter(|f| f.name.contains("__scrt_fastfail")).cloned().collect();

        self.analyze_functions(&mut functions)?;

        info!(
            "Analysis completed: {} functions ready for obfuscation",
            functions.len()
        );
        Ok(functions)
    }
}
