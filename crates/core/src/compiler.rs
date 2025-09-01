use crate::function::{AddressUpdatable, Encodable, ObfuscatorFunction, StateManaged};
use crate::pe::PEContext;
use std::cell::RefCell;
use std::rc::Rc;

pub struct CompilerContext {
    pe_context: Rc<RefCell<PEContext>>,
}

impl CompilerContext {
    pub fn new(pe_context: Rc<RefCell<PEContext>>) -> Self {
        Self { pe_context }
    }

    pub fn compile_functions(
        &mut self,
        functions: &mut [ObfuscatorFunction],
    ) -> Result<Vec<u8>, String> {
        let base_rva = self
            .pe_context
            .borrow()
            .get_next_section_rva()
            .map_err(|e| format!("Failed to get section RVA: {e}"))?;

        let (merged_bytes, _) =
            functions
                .iter_mut()
                .try_fold((Vec::new(), base_rva), |(mut bytes, rva), func| {
                    let encoded = func
                        .encode(rva)
                        .map_err(|e| format!("Failed to encode {}: {e}", func.name))?;

                    bytes.extend_from_slice(&encoded);
                    func.update_rva(rva as u32);
                    func.update_size(encoded.len() as u32);

                    Ok::<_, String>((bytes, rva + encoded.len() as u32))
                })?;

        self.trash_old_function_bytes(functions)?;
        self.patch_function_redirects(functions)?;

        self.pe_context
            .borrow_mut()
            .create_executable_section(".vasie", &merged_bytes)
            .map_err(|e| format!("Failed to create section: {e}"))?;

        Ok(merged_bytes)
    }

    fn trash_old_function_bytes(&self, functions: &[ObfuscatorFunction]) -> Result<(), String> {
        functions
            .iter()
            .filter(|f| f.get_original_size() > 5)
            .try_for_each(|func| {
                let rva = func.get_original_rva() + 5;
                let size = func.get_original_size() - 5;
                let bytes = vec![0xCC; size as usize];

                self.pe_context
                    .borrow_mut()
                    .write_data_at_rva(rva, &bytes)
                    .map_err(|e| format!("Failed to zero bytes at {rva:#x}: {e}"))
            })
    }

    fn patch_function_redirects(&self, functions: &[ObfuscatorFunction]) -> Result<(), String> {
        functions.iter().try_for_each(|func| {
            let src_rva = func.get_original_rva();
            let rel_offset = (func.rva as i64) - ((src_rva + 5) as i64);

            let mut jmp_bytes = [0xE9u8; 5];
            jmp_bytes[1..].copy_from_slice(&(rel_offset as i32).to_le_bytes());

            self.pe_context
                .borrow_mut()
                .write_data_at_rva(src_rva, &jmp_bytes)
                .map_err(|e| format!("Failed to patch JMP at {src_rva:#x}: {e}"))
        })
    }

    pub fn get_binary_data(self) -> Vec<u8> {
        self.pe_context.borrow().pe_data.clone()
    }
}
