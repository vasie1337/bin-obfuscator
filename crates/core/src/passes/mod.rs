use crate::function::RuntimeFunction;
use common::{error, debug};
pub mod mutation;

pub trait Pass {
    fn name(&self) -> &'static str;
    fn apply(&self, runtime_function: &mut RuntimeFunction) -> Result<(), String>;
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

    pub fn run_passes(&self, runtime_function: &mut RuntimeFunction, count: usize) {
        debug!("Running {} passes {} times on function {}", self.passes.len(), count, runtime_function.name);
        
        for iteration in 0..count {
            debug!("Pass iteration {} for function {}", iteration + 1, runtime_function.name);
            
            for pass in &self.passes {
                debug!("Applying pass '{}' to function {}", pass.name(), runtime_function.name);
                let pre_instruction_count = runtime_function.instructions.len();
                
                match pass.apply(runtime_function) {
                    Ok(_) => {
                        let post_instruction_count = runtime_function.instructions.len();
                        if pre_instruction_count != post_instruction_count {
                            debug!(
                                "Pass '{}' modified function {}: {} -> {} instructions", 
                                pass.name(), 
                                runtime_function.name,
                                pre_instruction_count,
                                post_instruction_count
                            );
                        } else {
                            debug!("Pass '{}' completed on function {} (no changes)", pass.name(), runtime_function.name);
                        }
                    },
                    Err(e) => {
                        error!("Failed to apply pass {} to function {}: {}", pass.name(), runtime_function.name, e);
                    }
                }
            }
        }
        
        debug!("Completed all pass iterations for function {}", runtime_function.name);
    }

    pub fn default() -> Self {
        let mut manager = Self::new();
        manager.add_pass(Box::new(mutation::MutationPass::new()));
        manager
    }
}

impl Default for PassManager {
    fn default() -> Self {
        Self::default()
    }
}
