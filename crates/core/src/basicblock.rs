use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_rva: u32,
    pub end_rva: u32,
    pub size: usize,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
    pub terminator: BlockTerminator,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockTerminator {
    UnconditionalJump {
        target: Option<u32>,
    },
    ConditionalJump {
        target: Option<u32>,
        fallthrough: u32,
    },
    Return,
    Call {
        target: Option<u32>,
        fallthrough: u32,
    },
    IndirectJump,
    Interrupt,
    EndOfFunction,
}
#[derive(Debug, Clone)]
pub struct SplitConfig {
    pub split_on_calls: bool,
    pub follow_indirect_jumps: bool,
    pub max_instructions_per_block: usize,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self {
            split_on_calls: false,
            follow_indirect_jumps: false,
            max_instructions_per_block: 1000,
        }
    }
}
pub fn split_into_basic_blocks(
    code: &[u8],
    function_rva: u32,
    config: &SplitConfig,
) -> Result<Vec<BasicBlock>, String> {
    if code.is_empty() {
        return Ok(Vec::new());
    }

    let leaders = find_block_leaders(code, function_rva, config)?;
    let blocks = build_blocks(code, function_rva, leaders, config)?;
    let blocks = link_predecessors(blocks);

    Ok(blocks)
}

/// Find all basic block leaders (instructions that start a block)
fn find_block_leaders(
    code: &[u8],
    function_rva: u32,
    config: &SplitConfig,
) -> Result<HashSet<u32>, String> {
    let mut leaders = HashSet::new();
    leaders.insert(function_rva);

    let mut decoder = Decoder::with_ip(64, code, function_rva as u64, DecoderOptions::NONE);
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let _inst_rva = instruction.ip() as u32;

        match instruction.flow_control() {
            FlowControl::UnconditionalBranch => {
                let next_rva = (instruction.next_ip()) as u32;
                if next_rva < function_rva + code.len() as u32 {
                    leaders.insert(next_rva);
                }

                if instruction.is_ip_rel_memory_operand() || instruction.near_branch_target() != 0 {
                    let target = instruction.near_branch_target() as u32;
                    if target >= function_rva && target < function_rva + code.len() as u32 {
                        leaders.insert(target);
                    }
                }
            }

            FlowControl::ConditionalBranch => {
                let next_rva = instruction.next_ip() as u32;
                if next_rva < function_rva + code.len() as u32 {
                    leaders.insert(next_rva);
                }

                let target = instruction.near_branch_target() as u32;
                if target >= function_rva && target < function_rva + code.len() as u32 {
                    leaders.insert(target);
                }
            }

            FlowControl::Call => {
                if config.split_on_calls {
                    let next_rva = instruction.next_ip() as u32;
                    if next_rva < function_rva + code.len() as u32 {
                        leaders.insert(next_rva);
                    }
                }
            }

            FlowControl::Return | FlowControl::Interrupt => {
                let next_rva = instruction.next_ip() as u32;
                if next_rva < function_rva + code.len() as u32 {
                    leaders.insert(next_rva);
                }
            }

            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                let next_rva = instruction.next_ip() as u32;
                if next_rva < function_rva + code.len() as u32 {
                    leaders.insert(next_rva);
                }
            }

            _ => {}
        }
    }

    Ok(leaders)
}

/// Build basic blocks from code and leaders
fn build_blocks(
    code: &[u8],
    function_rva: u32,
    leaders: HashSet<u32>,
    config: &SplitConfig,
) -> Result<Vec<BasicBlock>, String> {
    let mut blocks = Vec::new();
    let mut sorted_leaders: Vec<u32> = leaders.iter().copied().collect();
    sorted_leaders.sort();

    for i in 0..sorted_leaders.len() {
        let start_rva = sorted_leaders[i];
        let end_boundary = if i + 1 < sorted_leaders.len() {
            sorted_leaders[i + 1]
        } else {
            function_rva + code.len() as u32
        };

        let block = build_single_block(code, function_rva, start_rva, end_boundary, config)?;
        blocks.push(block);
    }

    Ok(blocks)
}

/// Build a single basic block
fn build_single_block(
    code: &[u8],
    function_rva: u32,
    start_rva: u32,
    end_boundary: u32,
    config: &SplitConfig,
) -> Result<BasicBlock, String> {
    let offset = (start_rva - function_rva) as usize;
    let max_length = (end_boundary - start_rva) as usize;

    if offset >= code.len() {
        return Err(format!("Invalid block start RVA: 0x{:X}", start_rva));
    }

    let block_code = &code[offset..offset + max_length.min(code.len() - offset)];
    let mut decoder = Decoder::with_ip(64, block_code, start_rva as u64, DecoderOptions::NONE);
    let mut instruction = Instruction::default();

    let mut successors = Vec::new();
    let mut terminator = BlockTerminator::EndOfFunction;
    let mut end_rva = start_rva;
    let mut inst_count = 0;

    while decoder.can_decode() {
        let _inst_ip = decoder.ip();
        decoder.decode_out(&mut instruction);
        end_rva = instruction.ip() as u32;
        inst_count += 1;

        if inst_count > config.max_instructions_per_block {
            return Err(format!(
                "Block at 0x{:X} exceeded max instruction count",
                start_rva
            ));
        }

        match instruction.flow_control() {
            FlowControl::UnconditionalBranch => {
                let target = instruction.near_branch_target();
                terminator = if target != 0 {
                    let target_rva = target as u32;
                    successors.push(target_rva);
                    BlockTerminator::UnconditionalJump {
                        target: Some(target_rva),
                    }
                } else {
                    BlockTerminator::IndirectJump
                };
                break;
            }

            FlowControl::ConditionalBranch => {
                let target = instruction.near_branch_target() as u32;
                let fallthrough = instruction.next_ip() as u32;
                successors.push(target);
                successors.push(fallthrough);
                terminator = BlockTerminator::ConditionalJump {
                    target: Some(target),
                    fallthrough,
                };
                break;
            }

            FlowControl::Return => {
                terminator = BlockTerminator::Return;
                break;
            }

            FlowControl::Call => {
                if config.split_on_calls {
                    let target = instruction.near_branch_target();
                    let fallthrough = instruction.next_ip() as u32;
                    successors.push(fallthrough);
                    if target != 0 {
                        terminator = BlockTerminator::Call {
                            target: Some(target as u32),
                            fallthrough,
                        };
                    } else {
                        terminator = BlockTerminator::Call {
                            target: None,
                            fallthrough,
                        };
                    }
                    break;
                }
            }

            FlowControl::Interrupt => {
                terminator = BlockTerminator::Interrupt;
                break;
            }

            FlowControl::IndirectBranch => {
                terminator = BlockTerminator::IndirectJump;
                break;
            }

            _ => {}
        }

        let next_ip = instruction.next_ip() as u32;
        if next_ip >= end_boundary {
            break;
        }
    }

    let size = (end_rva - start_rva) as usize + instruction.len();
    let block_bytes = code[offset..offset + size].to_vec();

    Ok(BasicBlock {
        start_rva,
        end_rva,
        size,
        successors,
        predecessors: Vec::new(), // Will be filled in link_predecessors
        terminator,
        bytes: block_bytes,
    })
}

/// Link predecessor relationships between blocks
fn link_predecessors(mut blocks: Vec<BasicBlock>) -> Vec<BasicBlock> {
    let mut predecessor_map: HashMap<u32, Vec<u32>> = HashMap::new();

    for block in &blocks {
        for &successor in &block.successors {
            predecessor_map
                .entry(successor)
                .or_insert_with(Vec::new)
                .push(block.start_rva);
        }
    }

    for block in &mut blocks {
        if let Some(preds) = predecessor_map.get(&block.start_rva) {
            block.predecessors = preds.clone();
        }
    }

    blocks
}
#[derive(Debug)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub entry_rva: u32,
    block_map: HashMap<u32, usize>,
}

impl ControlFlowGraph {
    pub fn new(blocks: Vec<BasicBlock>, entry_rva: u32) -> Self {
        let block_map: HashMap<u32, usize> = blocks
            .iter()
            .enumerate()
            .map(|(i, block)| (block.start_rva, i))
            .collect();

        Self {
            blocks,
            entry_rva,
            block_map,
        }
    }

    pub fn get_block(&self, rva: u32) -> Option<&BasicBlock> {
        self.block_map.get(&rva).map(|&idx| &self.blocks[idx])
    }

    pub fn entry_block(&self) -> Option<&BasicBlock> {
        self.get_block(self.entry_rva)
    }

    pub fn instruction_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|b| {
                let mut decoder =
                    Decoder::with_ip(64, &b.bytes, b.start_rva as u64, DecoderOptions::NONE);
                let mut count = 0;
                while decoder.can_decode() {
                    let _ = decoder.decode();
                    count += 1;
                }
                count
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_linear_block() {
        let code = vec![
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xBB, 0x02, 0x00, 0x00, 0x00, 0xC3,
        ];

        let config = SplitConfig::default();
        let blocks = split_into_basic_blocks(&code, 0x1000, &config).unwrap();

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_rva, 0x1000);
        assert!(matches!(blocks[0].terminator, BlockTerminator::Return));
    }

    #[test]
    fn test_conditional_jump() {
        let code = vec![
            0x85, 0xC0, 0x74, 0x07, 0xBB, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xBB, 0x02, 0x00, 0x00,
            0x00, 0xC3,
        ];

        let config = SplitConfig::default();
        let blocks = split_into_basic_blocks(&code, 0x1000, &config).unwrap();

        assert!(blocks.len() >= 2);
        assert!(matches!(
            blocks[0].terminator,
            BlockTerminator::ConditionalJump { .. }
        ));
    }
}
