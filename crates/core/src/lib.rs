pub fn obfuscate(pe_binary: &[u8]) -> Result<Vec<u8>, String> {
    Ok(pe_binary.to_vec())
}
