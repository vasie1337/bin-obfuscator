use crate::function::ObfuscatorFunction;
use crate::pe::PEContext;
use common::{debug, info};
use rand::seq::SliceRandom;
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
        obfuscator_functions: &mut Vec<ObfuscatorFunction>,
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

        debug!(
            "Shuffling {} functions for obfuscation",
            obfuscator_functions.len()
        );
        obfuscator_functions.shuffle(&mut rand::thread_rng());

        info!(
            "Encoding and merging {} functions into new section",
            obfuscator_functions.len()
        );
        let total_functions = obfuscator_functions.len();
        for (index, obfuscator_function) in obfuscator_functions.iter_mut().enumerate() {
            debug!(
                "Processing function {} ({}/{})",
                obfuscator_function.name,
                index + 1,
                total_functions
            );
            let function_bytes = match obfuscator_function.encode(current_rva).map_err(|e| {
                format!(
                    "Failed to encode function {}: {}",
                    obfuscator_function.name, e
                )
            }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    for instruction in &obfuscator_function.instructions {
                        println!(
                            "0x{:x}: {:?} - {}",
                            instruction.ip(),
                            instruction.code(),
                            instruction.to_string()
                        );
                    }
                    return Err(e);
                }
            };

            merged_bytes.extend_from_slice(&function_bytes);

            obfuscator_function.update_rva(current_rva as u32);
            obfuscator_function.update_size(function_bytes.len() as u32);

            debug!(
                "Encoded function {} with {} bytes at RVA {:#x}",
                obfuscator_function.name,
                function_bytes.len(),
                current_rva
            );

            if let Some(original) = obfuscator_function.get_original() {
                debug!(
                    "Function {} transformation: original RVA {:#x} -> new RVA {:#x}, original size {} -> new size {}, instructions {} -> {}",
                    obfuscator_function.name,
                    original.rva,
                    obfuscator_function.rva,
                    original.size,
                    obfuscator_function.size,
                    original.instructions.len(),
                    obfuscator_function.instructions.len()
                );
            }

            current_rva += function_bytes.len() as u64;
        }

        info!("Zeroing old function bytes and patching redirects");
        self.zero_old_function_bytes(obfuscator_functions)?;
        self.patch_function_redirects(obfuscator_functions)?;

        info!("Updating exception data");
        self.update_exception_data(obfuscator_functions)?;

        let (section_rva, section_size) = self
            .pe_context
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

    fn zero_old_function_bytes(
        &mut self,
        obfuscator_functions: &[ObfuscatorFunction],
    ) -> Result<(), String> {
        debug!(
            "Zeroing old function bytes for {} functions",
            obfuscator_functions.len()
        );

        for obfuscator_function in obfuscator_functions {
            let original_rva = obfuscator_function.get_original_rva();
            let original_size = obfuscator_function.get_original_size();

            if original_size > 5 {
                let remaining_bytes = original_size - 5;
                let interrupt_bytes = vec![0xCC; remaining_bytes as usize];

                let start_rva = original_rva + 5;

                self.pe_context
                    .borrow_mut()
                    .write_data_at_rva(start_rva, &interrupt_bytes)
                    .map_err(|e| {
                        format!("Failed to write interrupt bytes at {:#x}: {}", start_rva, e)
                    })?;
            } else {
                debug!(
                    "Skipping function {} - original instruction length {} is too small for interrupt filling",
                    obfuscator_function.name, original_size
                );
            }
        }
        Ok(())
    }

    fn patch_function_redirects(
        &mut self,
        obfuscator_functions: &[ObfuscatorFunction],
    ) -> Result<(), String> {
        debug!(
            "Patching function redirects for {} functions",
            obfuscator_functions.len()
        );

        for obfuscator_function in obfuscator_functions {
            let src_rva = obfuscator_function.get_original_rva();
            let dst_rva = obfuscator_function.rva;

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
                src_rva, dst_rva, rel32, obfuscator_function.name
            );
        }
        Ok(())
    }

    fn update_exception_data(
        &mut self,
        obfuscator_functions: &[ObfuscatorFunction],
    ) -> Result<(), String> {
        debug!(
            "Updating exception data for {} functions",
            obfuscator_functions.len()
        );
        let functions_with_unwind_data = obfuscator_functions
            .iter()
            .filter(|f| f.unwind_info_address.is_some())
            .collect::<Vec<_>>();
        self.pe_context
            .borrow_mut()
            .update_exception_data(&functions_with_unwind_data)?;
        Ok(())
    }

    pub fn get_binary_data(self) -> Vec<u8> {
        self.pe_context.borrow().pe_data.clone()
    }
}
