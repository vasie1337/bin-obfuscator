use crate::types::ControlFlowGraph;
use anyhow::Result;

pub trait TransformationPass {
    fn name(&self) -> &'static str;
    fn transform(&self, cfg: &mut ControlFlowGraph) -> Result<()>;
    fn enabled(&self) -> bool {
        true
    }
}

pub mod substitution;
pub mod opaque_branches;

pub use substitution::SubstitutionPass;
pub use opaque_branches::OpaqueBranchesPass;