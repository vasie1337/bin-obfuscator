use crate::binary::pe::PeFile;

struct FunctionDiscovery {
    pe_file: PeFile,
}

impl FunctionDiscovery {
    pub fn new(pe_file: PeFile) -> Self {
        Self { pe_file }
    }
}