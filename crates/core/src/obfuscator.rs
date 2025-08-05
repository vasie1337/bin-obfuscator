use crate::function::RuntimeFunction;
use crate::passes::PassManager;
use common::{info, debug};

pub struct Obfuscator {
    pass_manager: PassManager,
}

impl Obfuscator {
    pub fn new() -> Self {
        Self {
            pass_manager: PassManager::default(),
        }
    }

    pub fn with_pass_manager(pass_manager: PassManager) -> Self {
        Self { pass_manager }
    }

    pub fn obfuscate(&self, runtime_functions: &mut Vec<RuntimeFunction>) -> Result<(), String> {
        info!("Starting obfuscation with pass manager");
        debug!("Applying passes to {} runtime functions", runtime_functions.len());
        
        let total_functions = runtime_functions.len();
        for (index, runtime_function) in runtime_functions.iter_mut().enumerate() {
            debug!(
                "Obfuscating function {} ({}/{}) with {} instructions", 
                runtime_function.name, 
                index + 1, 
                total_functions,
                runtime_function.instructions.len()
            );
            
            let original_instruction_count = runtime_function.instructions.len();
            self.pass_manager.run_passes(runtime_function, 1);
            let new_instruction_count = runtime_function.instructions.len();
            
            debug!(
                "Function {} obfuscation complete: {} -> {} instructions ({}% change)",
                runtime_function.name,
                original_instruction_count,
                new_instruction_count,
                if original_instruction_count > 0 {
                    ((new_instruction_count as f64 / original_instruction_count as f64) * 100.0 - 100.0) as i32
                } else { 0 }
            );
        }
        
        info!("Obfuscation completed for all runtime functions");
        Ok(())
    }
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}
