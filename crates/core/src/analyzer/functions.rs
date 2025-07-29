use crate::analyzer::AnalyzerContext;
use iced_x86::Decoder;
use parsers::pdb::PDBContext;
use parsers::pe::PEContext;

impl AnalyzerContext {
    pub fn new(pe_context: PEContext, pdb_context: PDBContext) -> Self {
        Self {
            pe_context,
            pdb_context,
        }
    }

    // For each function in the context, we need to decode it using iced_x86
    pub fn analyze(&mut self) -> Result<(), String> {
        //let functions = self.pdb_context.get_functions();
        //for function in functions.iter() {
        //    let mut decoder = Decoder::with_ip(
        //        64,
        //        &[],
        //        function.rva as u64,
        //        iced_x86::DecoderOptions::NONE,
        //    );
        //    while decoder.can_decode() {
        //        let instruction = decoder.decode();
        //        function.instructions.push(instruction);
        //    }
        //}
        Ok(())
    }
}
