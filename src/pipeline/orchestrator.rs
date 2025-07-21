use crate::types::cfg::ControlFlowGraph;
use crate::pipeline::passes::{TransformationPass, SubstitutionPass};
use anyhow::Result;
use tracing::{info, debug, warn};

pub struct PipelineOrchestrator {
    passes: Vec<Box<dyn TransformationPass>>,
}

impl PipelineOrchestrator {
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
        }
    }

    pub fn default_pipeline(bitness: u32) -> Self {
        let mut orchestrator = Self::new();
        
        orchestrator.add_pass(Box::new(SubstitutionPass::new(bitness)));
        
        // orchestrator.add_pass(Box::new(ControlFlowFlattening::new()));
        
        orchestrator
    }

    pub fn add_pass(&mut self, pass: Box<dyn TransformationPass>) {
        info!("Adding pass '{}' to pipeline", pass.name());
        self.passes.push(pass);
    }

    pub fn clear_passes(&mut self) {
        info!("Clearing all passes from pipeline");
        self.passes.clear();
    }

    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    pub fn list_passes(&self) -> Vec<&str> {
        self.passes.iter().map(|pass| pass.name()).collect()
    }

    pub fn run_single(&self, cfg: &mut ControlFlowGraph) -> Result<()> {
        info!("Running pipeline on single CFG with {} passes", self.passes.len());
        
        for (index, pass) in self.passes.iter().enumerate() {
            if pass.enabled() {
                info!("Running pass '{}' ({}/{})", pass.name(), index + 1, self.passes.len());
                let start_time = std::time::Instant::now();
                
                match pass.transform(cfg) {
                    Ok(()) => {
                        let duration = start_time.elapsed();
                        debug!("Pass '{}' completed in {:?}", pass.name(), duration);
                    }
                    Err(e) => {
                        warn!("Pass '{}' failed: {}", pass.name(), e);
                        return Err(e);
                    }
                }
            } else {
                debug!("Pass '{}' is disabled, skipping", pass.name());
            }
        }
        
        info!("Pipeline execution complete for single CFG");
        Ok(())
    }

    pub fn run_all(&self, cfgs: &mut [ControlFlowGraph]) -> Result<()> {
        let cfg_count = cfgs.len();
        info!("Running pipeline on {} CFGs with {} passes", cfg_count, self.passes.len());
        
        let total_start_time = std::time::Instant::now();
        let mut total_errors = 0;

        for (cfg_index, cfg) in cfgs.iter_mut().enumerate() {
            debug!("Processing CFG {}/{}", cfg_index + 1, cfg_count);
            
            match self.run_single(cfg) {
                Ok(()) => {
                    debug!("CFG {} processed successfully", cfg_index + 1);
                }
                Err(e) => {
                    warn!("CFG {} failed: {}", cfg_index + 1, e);
                    total_errors += 1;
                }
            }
        }
        
        let total_duration = total_start_time.elapsed();
        
        if total_errors > 0 {
            warn!("Pipeline completed with {} errors out of {} CFGs in {:?}", 
                  total_errors, cfg_count, total_duration);
        } else {
            info!("Pipeline completed successfully for all {} CFGs in {:?}", 
                  cfg_count, total_duration);
        }
        
        Ok(())
    }
}

pub fn run(bitness: u32, ir: &Vec<ControlFlowGraph>) -> Vec<ControlFlowGraph> {
    info!("Running obfuscation pipeline on {} functions", ir.len());
    
    let orchestrator = PipelineOrchestrator::default_pipeline(bitness);
    
    let mut mutable_ir = ir.clone();
    
    match orchestrator.run_all(&mut mutable_ir) {
        Ok(()) => {
            info!("Pipeline complete - {} functions processed successfully", mutable_ir.len());
        }
        Err(e) => {
            warn!("Pipeline encountered errors: {}", e);
        }
    }
    
    mutable_ir
}
