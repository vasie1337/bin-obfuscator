use crate::function::ObfuscatorFunction;
use crate::passes::PassManager;
use common::{debug, info};

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

    pub fn obfuscate(
        &self,
        obfuscator_functions: &mut Vec<ObfuscatorFunction>,
    ) -> Result<(), String> {
        info!("Starting obfuscation with pass manager");
        debug!(
            "Applying passes to {} functions",
            obfuscator_functions.len()
        );

        let total_functions = obfuscator_functions.len();
        for (index, obfuscator_function) in obfuscator_functions.iter_mut().enumerate() {
            debug!(
                "Obfuscating function {} ({}/{}) with {} instructions",
                obfuscator_function.name,
                index + 1,
                total_functions,
                obfuscator_function.instructions.len()
            );

            let original_instruction_count = obfuscator_function.instructions.len();
            self.pass_manager.run_passes(obfuscator_function, 1);
            let new_instruction_count = obfuscator_function.instructions.len();

            debug!(
                "Function {} obfuscation complete: {} -> {} instructions ({}% change)",
                obfuscator_function.name,
                original_instruction_count,
                new_instruction_count,
                if original_instruction_count > 0 {
                    ((new_instruction_count as f64 / original_instruction_count as f64) * 100.0
                        - 100.0) as i32
                } else {
                    0
                }
            );
        }

        info!("Obfuscation completed for all functions");
        Ok(())
    }
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}
