use parsers::pe::PEContext;

pub struct CompilerContext {
    pub pe_context: PEContext,
}

impl CompilerContext {
    pub fn new(pe_context: PEContext) -> Self {
        Self { pe_context }
    }
}