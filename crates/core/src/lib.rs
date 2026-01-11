mod analysis;
mod bblock;
mod types;

pub use analysis::discover_functions;
pub use bblock::{
    BasicBlock, BlockTerminator, ControlFlowGraph, SplitConfig, split_into_basic_blocks,
};
pub use types::{FunctionInfo, FunctionSource};

use pelite::pe::{Pe, PeFile};
use std::collections::HashMap;

pub struct ObfuscationEngine<'a> {
    file: PeFile<'a>,
    functions: Vec<FunctionInfo>,
    basic_blocks: HashMap<u32, Vec<BasicBlock>>,
}

impl<'a> ObfuscationEngine<'a> {
    pub fn new(pe_binary: &'a [u8]) -> Result<Self, String> {
        let file = PeFile::from_bytes(pe_binary).map_err(|e| e.to_string())?;
        let functions = analysis::discover_functions(&file)?;

        Ok(Self {
            file,
            functions,
            basic_blocks: HashMap::new(),
        })
    }

    pub fn analyze(&mut self) -> Result<(), String> {
        println!("Found {} functions", self.functions.len());

        let stats = self
            .functions
            .iter()
            .fold(HashMap::new(), |mut stats, func| {
                *stats.entry(func.source.clone()).or_insert(0) += 1;
                stats
            });
        println!("Function sources: {:?}", stats);

        self.validate_functions()?;
        self.analyze_basic_blocks()?;

        Ok(())
    }

    fn validate_functions(&self) -> Result<(), String> {
        let functions_without_size = self.functions.iter().filter(|f| f.size.is_none()).count();
        if functions_without_size > 0 {
            return Err(format!(
                "FATAL: {} functions missing size information",
                functions_without_size
            ));
        }
        println!(
            "All {} functions have size information",
            self.functions.len()
        );

        for i in 0..self.functions.len().saturating_sub(1) {
            if let (Some(end1), start2) =
                (self.functions[i].end_rva, self.functions[i + 1].start_rva)
            {
                if end1 > start2 {
                    return Err(format!(
                        "FATAL: Function overlap at 0x{:08X} (ends 0x{:08X}) and 0x{:08X}",
                        self.functions[i].start_rva, end1, start2
                    ));
                }
            }
        }
        println!("No function overlaps detected");

        Ok(())
    }

    fn analyze_basic_blocks(&mut self) -> Result<(), String> {
        let config = SplitConfig::default();
        let mut total_blocks = 0;
        let mut analyzed_count = 0;

        for func in &self.functions {
            if func.source == FunctionSource::ExceptionHandler {
                continue;
            }

            let code = match self
                .file
                .derva_slice(func.start_rva, func.size.unwrap_or(0) as usize)
            {
                Ok(c) => c,
                Err(_) => continue,
            };

            match split_into_basic_blocks(code, func.start_rva, &config) {
                Ok(blocks) => {
                    total_blocks += blocks.len();
                    self.basic_blocks.insert(func.start_rva, blocks);
                    analyzed_count += 1;
                }
                Err(_) => continue,
            }
        }

        println!(
            "Analyzed {} functions into {} basic blocks",
            analyzed_count, total_blocks
        );
        println!(
            "Average {:.1} blocks per function",
            total_blocks as f64 / analyzed_count as f64
        );

        Ok(())
    }

    pub fn get_function_blocks(&self, rva: u32) -> Option<&Vec<BasicBlock>> {
        self.basic_blocks.get(&rva)
    }

    pub fn get_function_cfg(&self, rva: u32) -> Option<ControlFlowGraph> {
        self.basic_blocks
            .get(&rva)
            .map(|blocks| ControlFlowGraph::new(blocks.clone(), rva))
    }

    pub fn obfuscate(&self) -> Result<Vec<u8>, String> {
        println!("Starting obfuscation");

        let obfuscatable: Vec<_> = self
            .functions
            .iter()
            .filter(|f| f.source != FunctionSource::ExceptionHandler)
            .filter(|f| self.basic_blocks.contains_key(&f.start_rva))
            .collect();

        println!(
            "Functions available for obfuscation: {}",
            obfuscatable.len()
        );

        let mut sorted = obfuscatable.clone();
        sorted.sort_by(|a, b| b.size.cmp(&a.size));

        println!("Top 10 largest functions:");
        for func in sorted.iter().take(10) {
            let blocks = self
                .basic_blocks
                .get(&func.start_rva)
                .map(|b| b.len())
                .unwrap_or(0);
            println!(
                "  0x{:08X}: {} bytes, {} blocks, source: {:?}",
                func.start_rva,
                func.size.unwrap_or(0),
                blocks,
                func.source
            );
        }

        Ok(vec![])
    }
}

pub fn obfuscate(pe_binary: &[u8]) -> Result<Vec<u8>, String> {
    let mut engine = ObfuscationEngine::new(pe_binary)?;
    engine.analyze()?;
    engine.obfuscate()
}
