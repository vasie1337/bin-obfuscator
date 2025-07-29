use parsers::pdb::PDBFunction;
use iced_x86::Decoder;
use crate::analyzer::{AnalyzerContext, Function};

impl AnalyzerContext {
    pub fn new(pdb_functions: Vec<PDBFunction>) -> Self {
        Self {
            functions: pdb_functions.iter().map(|f| Function {
                pdb_function: f.clone(),
                instructions: vec![],
            }).collect(),
        }
    }

    // For each function in the context, we need to decode it using iced_x86
    pub fn analyze(&mut self) -> Result<(), String> {
        for function in &mut self.functions {
            let mut decoder = Decoder::with_ip(64, &[], function.pdb_function.rva as u64, iced_x86::DecoderOptions::NONE);
            while decoder.can_decode() {
                let instruction = decoder.decode();
                function.instructions.push(instruction);
            }
        }
        Ok(())
    }
}