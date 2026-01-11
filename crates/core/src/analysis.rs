use crate::types::{FunctionInfo, FunctionSource};
use pelite::pe::{Pe, PeFile};
use std::collections::HashSet;

pub fn discover_functions(file: &PeFile) -> Result<Vec<FunctionInfo>, String> {
    let mut functions = Vec::new();
    let mut seen_rvas = HashSet::new();

    let entry_point = file.optional_header().AddressOfEntryPoint;
    if entry_point != 0 && seen_rvas.insert(entry_point) {
        functions.push(FunctionInfo {
            start_rva: entry_point,
            end_rva: None,
            size: None,
            name: Some("EntryPoint".to_string()),
            source: FunctionSource::EntryPoint,
        });
    }

    if let Ok(exports) = file.exports() {
        if let Ok(by) = exports.by() {
            for (name_result, export_result) in by.iter_names() {
                if let (Ok(name_cstr), Ok(export)) = (name_result, export_result) {
                    if let Some(rva_val) = export.symbol() {
                        if seen_rvas.insert(rva_val) {
                            functions.push(FunctionInfo {
                                start_rva: rva_val,
                                end_rva: None,
                                size: None,
                                name: Some(name_cstr.to_string()),
                                source: FunctionSource::Export,
                            });
                        }
                    }
                }
            }

            for export_result in by.iter() {
                if let Ok(export) = export_result {
                    if let Some(rva_val) = export.symbol() {
                        if seen_rvas.insert(rva_val) {
                            functions.push(FunctionInfo {
                                start_rva: rva_val,
                                end_rva: None,
                                size: None,
                                name: None,
                                source: FunctionSource::Export,
                            });
                        }
                    }
                }
            }
        }
    }

    if let Ok(exception) = file.exception() {
        for func in exception.functions() {
            let begin_rva = func.image().BeginAddress;
            let end_rva = func.image().EndAddress;
            let size = end_rva - begin_rva;
            if seen_rvas.insert(begin_rva) {
                functions.push(FunctionInfo {
                    start_rva: begin_rva,
                    end_rva: Some(end_rva),
                    size: Some(size),
                    name: None,
                    source: FunctionSource::ExceptionHandler,
                });
            }
        }
    }

    if let Ok(tls) = file.tls() {
        if let Ok(callbacks) = tls.callbacks() {
            for callback in callbacks {
                if let Ok(rva) = file.va_to_rva(*callback) {
                    if seen_rvas.insert(rva) {
                        functions.push(FunctionInfo {
                            start_rva: rva,
                            end_rva: None,
                            size: None,
                            name: None,
                            source: FunctionSource::TlsCallback,
                        });
                    }
                }
            }
        }
    }

    Ok(functions)
}
