use std::fmt;

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub start_rva: u32,
    pub end_rva: Option<u32>,
    pub size: Option<u32>,
    pub name: Option<String>,
    pub source: FunctionSource,
}

impl fmt::Display for FunctionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Function: start_rva: {:08X}, end_rva: {:08X}, size: {:08X}, name: {:?}, source: {:?}",
            self.start_rva,
            self.end_rva.unwrap_or(0),
            self.size.unwrap_or(0),
            self.name,
            self.source
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FunctionSource {
    Export,
    ExceptionHandler,
    TlsCallback,
    EntryPoint,
}
