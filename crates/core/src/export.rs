use crate::{BasicBlock, BlockTerminator, FunctionInfo};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionExport {
    pub rva: String,
    pub size: usize,
    pub source: String,
    pub blocks: Vec<BlockExport>,
    pub edges: Vec<EdgeExport>,
    pub stats: BlockStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockExport {
    pub id: String,
    pub start_rva: String,
    pub end_rva: String,
    pub size: usize,
    pub terminator: String,
    pub bytes: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EdgeExport {
    pub from: String,
    pub to: String,
    pub edge_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockStats {
    pub total_blocks: usize,
    pub total_instructions: usize,
    pub return_blocks: usize,
    pub has_loops: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryExport {
    pub binary_name: String,
    pub functions: Vec<FunctionExport>,
    pub summary: Summary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Summary {
    pub total_functions: usize,
    pub total_blocks: usize,
    pub total_instructions: usize,
    pub avg_blocks_per_function: f64,
}

impl FunctionExport {
    pub fn from_function(
        func: &FunctionInfo,
        blocks: &[BasicBlock],
    ) -> Self {
        let blocks_export: Vec<BlockExport> = blocks
            .iter()
            .map(|b| BlockExport {
                id: format!("{:08X}", b.start_rva),
                start_rva: format!("0x{:08X}", b.start_rva),
                end_rva: format!("0x{:08X}", b.end_rva),
                size: b.size,
                terminator: format!("{:?}", b.terminator),
                bytes: hex::encode(&b.bytes),
            })
            .collect();

        let mut edges = Vec::new();
        for block in blocks {
            for &succ in &block.successors {
                let edge_type = match &block.terminator {
                    BlockTerminator::UnconditionalJump { .. } => "unconditional",
                    BlockTerminator::ConditionalJump { target, .. } => {
                        if target == &Some(succ) {
                            "conditional_taken"
                        } else {
                            "conditional_fallthrough"
                        }
                    }
                    BlockTerminator::Call { .. } => "call",
                    _ => "other",
                };

                edges.push(EdgeExport {
                    from: format!("{:08X}", block.start_rva),
                    to: format!("{:08X}", succ),
                    edge_type: edge_type.to_string(),
                });
            }
        }

        let return_blocks = blocks
            .iter()
            .filter(|b| matches!(b.terminator, BlockTerminator::Return))
            .count();

        let has_loops = blocks.iter().any(|b| {
            b.successors.iter().any(|&succ| succ <= b.start_rva)
        });

        let total_instructions = count_instructions(blocks);

        FunctionExport {
            rva: format!("0x{:08X}", func.start_rva),
            size: func.size.unwrap_or(0) as usize,
            source: format!("{:?}", func.source),
            blocks: blocks_export,
            edges,
            stats: BlockStats {
                total_blocks: blocks.len(),
                total_instructions,
                return_blocks,
                has_loops,
            },
        }
    }
}

impl BinaryExport {
    pub fn new(
        binary_name: String,
        functions_data: Vec<(&FunctionInfo, &Vec<BasicBlock>)>,
    ) -> Self {
        let functions: Vec<FunctionExport> = functions_data
            .iter()
            .map(|(func, blocks)| FunctionExport::from_function(func, blocks))
            .collect();

        let total_functions = functions.len();
        let total_blocks: usize = functions.iter().map(|f| f.blocks.len()).sum();
        let total_instructions: usize = functions.iter().map(|f| f.stats.total_instructions).sum();
        let avg_blocks_per_function = if total_functions > 0 {
            total_blocks as f64 / total_functions as f64
        } else {
            0.0
        };

        BinaryExport {
            binary_name,
            functions,
            summary: Summary {
                total_functions,
                total_blocks,
                total_instructions,
                avg_blocks_per_function,
            },
        }
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

fn count_instructions(blocks: &[BasicBlock]) -> usize {
    use iced_x86::{Decoder, DecoderOptions};

    blocks
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
