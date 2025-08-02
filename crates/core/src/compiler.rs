use crate::function::RuntimeFunction;
use common::{debug, info};
use parsers::pe::PEContext;

pub struct CompilerContext {
    pub pe_context: PEContext,
}

impl CompilerContext {
    pub fn new(pe_context: PEContext) -> Self {
        Self {
            pe_context,
        }
    }

    pub fn compile_functions(&mut self, runtime_functions: &mut Vec<RuntimeFunction>) -> Result<Vec<u8>, String> {
        let section_base_rva = self
            .pe_context
            .get_next_section_rva()
            .map_err(|e| format!("Failed to get next section RVA: {}", e))?;

        let mut current_rva = section_base_rva;
        let mut merged_bytes = Vec::new();

        for runtime_function in runtime_functions.iter_mut() {
            let function_bytes = runtime_function.encode(current_rva).map_err(|e| {
                format!("Failed to encode function {}: {}", runtime_function.name, e)
            })?;

            merged_bytes.extend_from_slice(&function_bytes);

            runtime_function.update_rva(current_rva as u32);
            runtime_function.update_size(function_bytes.len() as u32);

            debug!(
                "Encoded function {} with {} bytes at RVA {:#x}",
                runtime_function.name,
                function_bytes.len(),
                current_rva
            );

            if let Some(original) = runtime_function.get_original() {
                debug!(
                    "Function {} transformation: original RVA {:#x} -> new RVA {:#x}, original size {} -> new size {}, instructions {} -> {}",
                    runtime_function.name,
                    original.rva,
                    runtime_function.rva,
                    original.size,
                    runtime_function.size,
                    original.instructions.len(),
                    runtime_function.instructions.len()
                );
            }

            current_rva += function_bytes.len() as u64;
        }

        self.patch_function_redirects(runtime_functions)?;

        self.pe_context
            .create_executable_section(".vasie", &merged_bytes)
            .map_err(|e| format!("Failed to create executable section: {}", e))?;

        info!("Created .vasie section with {} bytes", merged_bytes.len());

        Ok(merged_bytes)
    }

    fn patch_function_redirects(
        &mut self,
        runtime_functions: &[RuntimeFunction],
    ) -> Result<(), String> {
        for runtime_function in runtime_functions {
            let src_rva = runtime_function.get_original_rva();
            let dst_rva = runtime_function.rva;

            let relative_offset = (dst_rva as i64) - ((src_rva + 5) as i64);
            let rel32 = relative_offset as i32;

            let mut jmp_bytes = [0u8; 5];
            jmp_bytes[0] = 0xE9;
            jmp_bytes[1..].copy_from_slice(&rel32.to_le_bytes());

            self.pe_context
                .write_data_at_rva(src_rva, &jmp_bytes)
                .map_err(|e| format!("Failed to patch JMP at {:#x}: {}", src_rva, e))?;

            debug!(
                "Patched JMP at 0x{:x} to 0x{:x} (rel_offset: 0x{:x})",
                src_rva, dst_rva, rel32
            );
        }

        info!("Patched {} JMP instructions", runtime_functions.len());

        Ok(())
    }

    pub fn get_binary_data(self) -> Vec<u8> {
        self.pe_context.pe_data
    }
}
