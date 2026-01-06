//! Obfuscation passes for transforming instructions.
//! 
//! Each pass focuses on a specific category of transformations:
//! - `arithmetic`: LEA displacement obfuscation, constant splitting
//! - `stack`: PUSH/POP to explicit MOV+LEA sequences
//! - `control_flow`: Call obfuscation (call → lea+push+jmp)
//! - `opaque_predicates`: Insert always-true/false computations

use crate::function::ObfuscatorFunction;
use ::common::{debug, error};

mod utils;
pub mod arithmetic;
pub mod stack;
pub mod control_flow;
pub mod opaque_predicates;

// Re-export passes
pub use arithmetic::ArithmeticPass;
pub use stack::StackPass;
pub use control_flow::ControlFlowPass;
pub use opaque_predicates::OpaquePredicatesPass;

/// Trait for all obfuscation passes.
pub trait Pass {
    /// Human-readable name of the pass.
    fn name(&self) -> &'static str;
    
    /// Apply the pass to a function's instructions.
    fn apply(&self, function: &mut ObfuscatorFunction) -> Result<(), String>;
    
    /// Whether this pass is enabled by default.
    fn enabled_by_default(&self) -> bool {
        true
    }
}

/// Manages and runs obfuscation passes.
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
        // Add all passes in order
        manager.add_pass(Box::new(ArithmeticPass::new()));
        manager.add_pass(Box::new(StackPass::new()));
        manager.add_pass(Box::new(ControlFlowPass::new()));
        manager.add_pass(Box::new(OpaquePredicatesPass::new()));
        manager
    }
}
