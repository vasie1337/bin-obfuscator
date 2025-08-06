use crate::function::ObfuscatorFunction;
use common::{debug, error};
pub mod mutation;

pub trait Pass {
    fn name(&self) -> &'static str;
    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String>;
    fn enabled_by_default(&self) -> bool {
        true
    }
}

pub struct PassManager {
    passes: Vec<Box<dyn Pass>>,
}

impl PassManager {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    pub fn add_pass(&mut self, pass: Box<dyn Pass>) {
        self.passes.push(pass);
    }

    pub fn run_passes(&self, function: &mut ObfuscatorFunction, count: usize) {
        debug!(
            "Running {} passes {} times on function {}",
            self.passes.len(),
            count,
            function.name
        );

        for iteration in 0..count {
            debug!(
                "Pass iteration {} for function {}",
                iteration + 1,
                function.name
            );

            for pass in &self.passes {
                debug!(
                    "Applying pass '{}' to function {}",
                    pass.name(),
                    function.name
                );
                let pre_instruction_count = function.instructions.len();

                match pass.apply(function) {
                    Ok(_) => {
                        let post_instruction_count = function.instructions.len();
                        if pre_instruction_count != post_instruction_count {
                            debug!(
                                "Pass '{}' modified function {}: {} -> {} instructions",
                                pass.name(),
                                function.name,
                                pre_instruction_count,
                                post_instruction_count
                            );
                        } else {
                            debug!(
                                "Pass '{}' completed on function {} (no changes)",
                                pass.name(),
                                function.name
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to apply pass {} to function {}: {}",
                            pass.name(),
                            function.name,
                            e
                        );
                    }
                }
            }
        }

        debug!(
            "Completed all pass iterations for function {}",
            function.name
        );
    }
}

impl Default for PassManager {
    fn default() -> Self {
        let mut manager = Self::new();
        manager.add_pass(Box::new(mutation::MutationPass::new()));
        manager
    }
}
