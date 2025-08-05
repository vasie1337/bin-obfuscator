use crate::function::RuntimeFunction;
use crate::passes::PassManager;

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
        for runtime_function in runtime_functions.iter_mut() {
            self.pass_manager.run_passes(runtime_function, 1);
        }
        Ok(())
    }
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}
