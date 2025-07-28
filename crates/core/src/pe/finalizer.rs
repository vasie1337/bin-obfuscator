use common::info;
use crate::pe::PEContext;

impl PEContext {
    pub fn finalize(&self) {
        info!("Finalizing PE...");
    }
}