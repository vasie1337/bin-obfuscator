use crate::analyzer::{AnalyzerContext, RuntimeFunction};
use common::info;
use iced_x86::{Decoder, FlowControl};
use parsers::pdb::{PDBContext, PDBFunction};
use parsers::pe::PEContext;

impl RuntimeFunction {
    pub fn new(pdb_function: PDBFunction) -> Self {
        Self {
            pdb_function,
            instructions: vec![],
        }
    }

    fn decode(&mut self, pe_context: &PEContext) -> Result<(), String> {
        let bytes = pe_context
            .read_data_at_rva(self.pdb_function.rva, self.pdb_function.size as usize)
            .map_err(|e| {
                format!(
                    "Failed to read function bytes at RVA {:#x}: {}",
                    self.pdb_function.rva, e
                )
            })?;

        let estimated_instruction_count = (bytes.len() / 3).max(16);
        let mut instructions = Vec::with_capacity(estimated_instruction_count);

        let mut decoder = Decoder::with_ip(
            64,
            &bytes,
            self.pdb_function.rva as u64,
            iced_x86::DecoderOptions::NONE,
        );

        while decoder.can_decode() {
            let instruction = decoder.decode();
            instructions.push(instruction);
        }

        instructions.shrink_to_fit();

        self.instructions = instructions;

        Ok(())
    }
}

impl AnalyzerContext {
    pub fn new(pe_context: PEContext, pdb_context: PDBContext) -> Self {
        Self {
            pe_context,
            pdb_context,
        }
    }

    pub fn analyze(&mut self) -> Result<Vec<RuntimeFunction>, String> {
        let pdb_functions = self.pdb_context.get_functions();

        let mut runtime_functions = Vec::with_capacity(pdb_functions.len());

        for pdb_function in pdb_functions {
            let function_name = pdb_function.name.clone();
            let function_rva = pdb_function.rva;
            let mut runtime_function = RuntimeFunction::new(pdb_function);
            match runtime_function.decode(&self.pe_context) {
                Ok(_) => runtime_functions.push(runtime_function),
                Err(e) => {
                    info!("Failed to analyze function {:#x} {}: {}", function_rva, function_name, e);
                }
            }
        }

        Ok(runtime_functions)
    }
}
