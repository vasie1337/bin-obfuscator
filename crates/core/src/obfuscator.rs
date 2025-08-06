use crate::function::ObfuscatorFunction;
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

    pub fn obfuscate(&self, functions: &mut [ObfuscatorFunction]) -> Result<(), String> {
        functions.iter_mut().for_each(|function| {
            self.pass_manager.run_passes(function, 1);
        });
        Ok(())
    }
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}
