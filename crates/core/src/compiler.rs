use rand::seq::SliceRandom;
use crate::function::RuntimeFunction;
use common::{debug, info};
use crate::pe::PEContext;
use std::cell::RefCell;
use std::rc::Rc;

pub struct CompilerContext {
    pub pe_context: Rc<RefCell<PEContext>>,
}

impl CompilerContext {
    pub fn new(pe_context: Rc<RefCell<PEContext>>) -> Self {
        Self { pe_context }
    }

    pub fn compile_functions(
        &mut self,
        runtime_functions: &mut Vec<RuntimeFunction>,
    ) -> Result<Vec<u8>, String> {
        info!("Starting function compilation process");
        
        let section_base_rva = self
            .pe_context
            .borrow()
            .get_next_section_rva()
            .map_err(|e| format!("Failed to get next section RVA: {}", e))?;

        info!("New section will start at RVA {:#x}", section_base_rva);
        
        let mut current_rva = section_base_rva;
        let mut merged_bytes = Vec::new();

        debug!("Shuffling {} runtime functions for obfuscation", runtime_functions.len());
        runtime_functions.shuffle(&mut rand::thread_rng());

        info!("Encoding and merging {} functions into new section", runtime_functions.len());
        let total_functions = runtime_functions.len();
        for (index, runtime_function) in runtime_functions.iter_mut().enumerate() {
            debug!("Processing function {} ({}/{})", runtime_function.name, index + 1, total_functions);
            let function_bytes = match runtime_function.encode(current_rva).map_err(|e| {
                format!("Failed to encode function {}: {}", runtime_function.name, e)
            }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    for instruction in &runtime_function.instructions {
                        println!("0x{:x}: {:?} - {}", instruction.ip(), instruction.code(), instruction.to_string());
                    }
                    return Err(e);
                }
            };

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

        info!("Zeroing old function bytes and patching redirects");
        self.zero_old_function_bytes(runtime_functions)?;
        self.patch_function_redirects(runtime_functions)?;

        info!("Updating exception data");
        self.update_exception_data(runtime_functions)?;

        let (section_rva, section_size) = self.pe_context
            .borrow_mut()
            .create_executable_section(".vasie", &merged_bytes)
            .map_err(|e| format!("Failed to create executable section: {}", e))?;

        info!(
            "Created .vasie section with {} bytes at RVA {:#x} (virtual size: {})", 
            merged_bytes.len(), 
            section_rva, 
            section_size
        );

        Ok(merged_bytes)
    }

    fn zero_old_function_bytes(&mut self, runtime_functions: &[RuntimeFunction]) -> Result<(), String> {
        debug!("Zeroing old function bytes for {} functions", runtime_functions.len());
        
        for runtime_function in runtime_functions {
            let original_rva = runtime_function.get_original_rva();
            let original_size = runtime_function.get_original_size();
            
            if original_size > 5 {
                let remaining_bytes = original_size - 5;
                let interrupt_bytes = vec![0xCC; remaining_bytes as usize];
                
                let start_rva = original_rva + 5;
                
                self.pe_context
                    .borrow_mut()
                    .write_data_at_rva(start_rva, &interrupt_bytes)
                    .map_err(|e| format!("Failed to write interrupt bytes at {:#x}: {}", start_rva, e))?;
            } else {
                debug!(
                    "Skipping function {} - original instruction length {} is too small for interrupt filling",
                    runtime_function.name, original_size
                );
            }
        }
        Ok(())
    }

    fn patch_function_redirects(
        &mut self,
        runtime_functions: &[RuntimeFunction],
    ) -> Result<(), String> {
        debug!("Patching function redirects for {} functions", runtime_functions.len());
        
        for runtime_function in runtime_functions {
            let src_rva = runtime_function.get_original_rva();
            let dst_rva = runtime_function.rva;

            let relative_offset = (dst_rva as i64) - ((src_rva + 5) as i64);
            let rel32 = relative_offset as i32;

            let mut jmp_bytes = [0u8; 5];
            jmp_bytes[0] = 0xE9;
            jmp_bytes[1..].copy_from_slice(&rel32.to_le_bytes());

            self.pe_context
                .borrow_mut()
                .write_data_at_rva(src_rva, &jmp_bytes)
                .map_err(|e| format!("Failed to patch JMP at {:#x}: {}", src_rva, e))?;

            debug!(
                "Patched JMP at 0x{:x} to 0x{:x} (rel_offset: 0x{:x}) for function {}",
                src_rva, dst_rva, rel32, runtime_function.name
            );
        }
        Ok(())
    }

    fn update_exception_data(&mut self, runtime_functions: &[RuntimeFunction]) -> Result<(), String> {
        debug!("Updating exception data for {} functions", runtime_functions.len());
        self.pe_context
        .borrow_mut()
        .update_exception_data(&runtime_functions)?;
        Ok(())
    }

    pub fn get_binary_data(self) -> Vec<u8> {
        self.pe_context.borrow().pe_data.clone()
    }
}
