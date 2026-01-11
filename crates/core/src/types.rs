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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FunctionSource {
    EntryPoint, // Highest priority
    Export,
    ExceptionHandler,
    TlsCallback,
    CallTarget, // Lowest priority
}

impl FunctionSource {
    /// Returns the priority of the source (lower number = higher priority)
    pub fn priority(&self) -> u8 {
        match self {
            FunctionSource::EntryPoint => 0,
            FunctionSource::Export => 1,
            FunctionSource::ExceptionHandler => 2,
            FunctionSource::TlsCallback => 3,
            FunctionSource::CallTarget => 4,
        }
    }
}
