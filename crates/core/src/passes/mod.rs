use crate::function::RuntimeFunction;
use iced_x86::Instruction;

pub mod mutation;

pub trait Pass {
    fn name(&self) -> &'static str;
    fn apply(&self, instructions: &[Instruction]) -> Vec<Instruction>;
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
        for _ in 0..count {
            for pass in &self.passes {
                runtime_function.instructions = pass.apply(&runtime_function.instructions);
            }
        }
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
