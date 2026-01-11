use crate::types::{FunctionInfo, FunctionSource};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use pelite::pe::{Pe, PeFile};
use std::collections::HashMap;

pub fn discover_functions(file: &PeFile) -> Result<Vec<FunctionInfo>, String> {
    let mut candidates = HashMap::new();

    discover_from_entry_point(file, &mut candidates);
    discover_from_exports(file, &mut candidates);
    discover_from_exceptions(file, &mut candidates);
    discover_from_tls(file, &mut candidates);

    discover_from_call_targets(file, &mut candidates)?;

    let mut functions = resolve_conflicts(candidates);

    calculate_function_sizes(file, &mut functions)?;

    Ok(functions)
}

fn discover_from_entry_point(file: &PeFile, candidates: &mut HashMap<u32, FunctionInfo>) {
    let entry_point = file.optional_header().AddressOfEntryPoint;
    if entry_point != 0 {
        candidates.insert(
            entry_point,
            FunctionInfo {
                start_rva: entry_point,
                end_rva: None,
                size: None,
                name: Some("EntryPoint".to_string()),
                source: FunctionSource::EntryPoint,
            },
        );
    }
}

fn discover_from_exports(file: &PeFile, candidates: &mut HashMap<u32, FunctionInfo>) {
    if let Ok(exports) = file.exports() {
        if let Ok(by) = exports.by() {
            for (name_result, export_result) in by.iter_names() {
                if let (Ok(name_cstr), Ok(export)) = (name_result, export_result) {
                    if let Some(rva_val) = export.symbol() {
                        add_or_upgrade_candidate(
                            candidates,
                            rva_val,
                            None,
                            None,
                            Some(name_cstr.to_string()),
                            FunctionSource::Export,
                        );
                    }
                }
            }

            for export_result in by.iter() {
                if let Ok(export) = export_result {
                    if let Some(rva_val) = export.symbol() {
                        add_or_upgrade_candidate(
                            candidates,
                            rva_val,
                            None,
                            None,
                            None,
                            FunctionSource::Export,
                        );
                    }
                }
            }
        }
    }
}

fn discover_from_exceptions(file: &PeFile, candidates: &mut HashMap<u32, FunctionInfo>) {
    if let Ok(exception) = file.exception() {
        for func in exception.functions() {
            let begin_rva = func.image().BeginAddress;
            let end_rva = func.image().EndAddress;
            let size = end_rva - begin_rva;
            add_or_upgrade_candidate(
                candidates,
                begin_rva,
                Some(end_rva),
                Some(size),
                None,
                FunctionSource::ExceptionHandler,
            );
        }
    }
}

fn discover_from_tls(file: &PeFile, candidates: &mut HashMap<u32, FunctionInfo>) {
    if let Ok(tls) = file.tls() {
        if let Ok(callbacks) = tls.callbacks() {
            for callback in callbacks {
                if let Ok(rva) = file.va_to_rva(*callback) {
                    add_or_upgrade_candidate(
                        candidates,
                        rva,
                        None,
                        None,
                        None,
                        FunctionSource::TlsCallback,
                    );
                }
            }
        }
    }
}

fn discover_from_call_targets(
    file: &PeFile,
    candidates: &mut HashMap<u32, FunctionInfo>,
) -> Result<(), String> {
    let image_base = file.optional_header().ImageBase;
    let bitness = match file.optional_header().Magic {
        0x20b => 64, // PE32+ (64-bit)
        0x10b => 32, // PE32 (32-bit)
        magic => return Err(format!("Unknown PE magic: 0x{:x}", magic)),
    };

    for section in file.section_headers() {
        if (section.Characteristics & 0x20000000) == 0 {
            continue;
        }

        let section_rva = section.VirtualAddress;
        let section_data = match file.derva_slice(section_rva, section.VirtualSize as usize) {
            Ok(data) => data,
            Err(_) => continue,
        };

        let mut decoder = Decoder::with_ip(
            bitness,
            section_data,
            image_base + section_rva as u64,
            DecoderOptions::NONE,
        );

        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if instruction.flow_control() == FlowControl::Call {
                if let Some(target_rva) = resolve_call_target(file, &instruction) {
                    if is_in_executable_section(file, target_rva) {
                        add_or_upgrade_candidate(
                            candidates,
                            target_rva,
                            None,
                            None,
                            None,
                            FunctionSource::CallTarget,
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn resolve_call_target(file: &PeFile, instruction: &Instruction) -> Option<u32> {
    if instruction.op_kind(0) == OpKind::NearBranch64
        || instruction.op_kind(0) == OpKind::NearBranch32
    {
        let target_va = instruction.near_branch_target();
        if let Ok(rva) = file.va_to_rva(target_va) {
            return Some(rva);
        }
    }

    if instruction.op_count() == 1 && instruction.op_kind(0) == OpKind::Memory {
        if instruction.is_ip_rel_memory_operand() {
            let target_va = instruction.ip_rel_memory_address();
            if let Ok(rva) = file.va_to_rva(target_va) {
                let is_64bit = file.optional_header().Magic == 0x20b;
                let ptr_size = if is_64bit { 8 } else { 4 };

                if let Ok(ptr_bytes) = file.derva_slice(rva, ptr_size) {
                    let ptr_va = if is_64bit {
                        u64::from_le_bytes(ptr_bytes[0..8].try_into().ok()?)
                    } else {
                        u32::from_le_bytes(ptr_bytes[0..4].try_into().ok()?) as u64
                    };

                    if let Ok(target_rva) = file.va_to_rva(ptr_va) {
                        return Some(target_rva);
                    }
                }
            }
        }
    }

    None
}

fn is_in_executable_section(file: &PeFile, rva: u32) -> bool {
    for section in file.section_headers() {
        let section_start = section.VirtualAddress;
        let section_end = section_start + section.VirtualSize;

        if rva >= section_start && rva < section_end {
            return (section.Characteristics & 0x20000000) != 0;
        }
    }
    false
}

fn add_or_upgrade_candidate(
    candidates: &mut HashMap<u32, FunctionInfo>,
    start_rva: u32,
    end_rva: Option<u32>,
    size: Option<u32>,
    name: Option<String>,
    source: FunctionSource,
) {
    if let Some(existing) = candidates.get_mut(&start_rva) {
        if source.priority() < existing.source.priority() {
            existing.source = source;
            if name.is_some() {
                existing.name = name;
            }
            if end_rva.is_some() {
                existing.end_rva = end_rva;
            }
            if size.is_some() {
                existing.size = size;
            }
        } else if source.priority() == existing.source.priority() {
            if existing.name.is_none() && name.is_some() {
                existing.name = name;
            }
            if existing.end_rva.is_none() && end_rva.is_some() {
                existing.end_rva = end_rva;
            }
            if existing.size.is_none() && size.is_some() {
                existing.size = size;
            }
        }
    } else {
        candidates.insert(
            start_rva,
            FunctionInfo {
                start_rva,
                end_rva,
                size,
                name,
                source,
            },
        );
    }
}

fn resolve_conflicts(candidates: HashMap<u32, FunctionInfo>) -> Vec<FunctionInfo> {
    let mut functions: Vec<FunctionInfo> = candidates.into_values().collect();

    functions.sort_by_key(|f| f.start_rva);

    let mut i = 0;
    while i < functions.len() {
        if i + 1 >= functions.len() {
            break;
        }

        let current = &functions[i];
        let next = &functions[i + 1];

        if let Some(current_end) = current.end_rva {
            if next.start_rva < current_end {
                if next.source.priority() < current.source.priority() {
                    functions.remove(i);
                    continue;
                } else {
                    functions.remove(i + 1);
                    continue;
                }
            }
        }

        i += 1;
    }

    functions
}

fn calculate_function_sizes(
    file: &PeFile,
    functions: &mut Vec<FunctionInfo>,
) -> Result<(), String> {
    if functions.is_empty() {
        return Ok(());
    }

    let sections: Vec<_> = file
        .section_headers()
        .iter()
        .filter(|s| (s.Characteristics & 0x20000000) != 0)
        .map(|s| (s.VirtualAddress, s.VirtualAddress + s.VirtualSize))
        .collect();

    let bitness = match file.optional_header().Magic {
        0x20b => 64,
        0x10b => 32,
        magic => return Err(format!("Unknown PE magic: 0x{:x}", magic)),
    };
    let image_base = file.optional_header().ImageBase;

    let end_rvas: Vec<Option<u32>> = (0..functions.len())
        .map(|i| {
            let func = &functions[i];

            if func.size.is_some() && func.end_rva.is_some() {
                return func.end_rva;
            }

            let start_rva = func.start_rva;

            let section_end = sections
                .iter()
                .find(|(start, end)| start_rva >= *start && start_rva < *end)
                .map(|(_, end)| *end)?;

            let end_rva = if i + 1 < functions.len() {
                let next_start = functions[i + 1].start_rva;

                if next_start < section_end {
                    next_start
                } else {
                    find_function_end(file, start_rva, section_end, bitness, image_base)
                        .unwrap_or(section_end)
                }
            } else {
                find_function_end(file, start_rva, section_end, bitness, image_base)
                    .unwrap_or(section_end)
            };

            Some(end_rva)
        })
        .collect();

    for (i, end_rva) in end_rvas.into_iter().enumerate() {
        if let Some(end) = end_rva {
            let func = &mut functions[i];
            func.end_rva = Some(end);
            func.size = Some(end.saturating_sub(func.start_rva));
        }
    }

    Ok(())
}

fn find_function_end(
    file: &PeFile,
    start_rva: u32,
    section_end: u32,
    bitness: u32,
    image_base: u64,
) -> Option<u32> {
    const MAX_SCAN_SIZE: u32 = 16384;

    let scan_end = std::cmp::min(start_rva + MAX_SCAN_SIZE, section_end);
    let scan_size = (scan_end - start_rva) as usize;

    let code = file.derva_slice(start_rva, scan_size).ok()?;

    let mut decoder = Decoder::with_ip(
        bitness,
        code,
        image_base + start_rva as u64,
        DecoderOptions::NONE,
    );

    let mut instruction = Instruction::default();
    let mut last_ret_end = None;

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        if !instruction.is_invalid() {
            match instruction.flow_control() {
                FlowControl::Return => {
                    let instr_end = decoder.ip() - image_base;
                    last_ret_end = Some(instr_end as u32);

                    if is_padding_after(file, instr_end as u32, section_end) {
                        return Some(instr_end as u32);
                    }
                }
                FlowControl::IndirectBranch | FlowControl::UnconditionalBranch => {}
                _ => {}
            }
        } else {
            if let Some(ret_end) = last_ret_end {
                return Some(ret_end);
            }
            break;
        }
    }

    last_ret_end
}

fn is_padding_after(file: &PeFile, rva: u32, section_end: u32) -> bool {
    const PADDING_CHECK_SIZE: usize = 16;

    let check_size = std::cmp::min(PADDING_CHECK_SIZE, (section_end - rva) as usize);
    if check_size == 0 {
        return true;
    }

    let Ok(bytes) = file.derva_slice::<u8>(rva, check_size) else {
        return false;
    };

    let padding_count = bytes
        .iter()
        .take_while(|&&b| {
            b == 0xCC || // INT3
            b == 0x90 || // NOP
            b == 0x00 // NULL
        })
        .count();

    padding_count >= 4
}
