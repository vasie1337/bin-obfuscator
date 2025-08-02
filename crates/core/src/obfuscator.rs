use crate::function::RuntimeFunction;
use crate::passes::PassManager;
use common::info;

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
        info!("Starting obfuscation of {} functions", runtime_functions.len());
        
        for runtime_function in runtime_functions.iter_mut() {
            runtime_function.capture_original_state();
            
            self.pass_manager.run_passes(runtime_function, 1);
            
            info!("Obfuscated function: {}", runtime_function.name);
        }
        
        info!("Completed obfuscation of {} functions", runtime_functions.len());
        Ok(())
    }
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}
