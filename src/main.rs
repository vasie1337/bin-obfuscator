mod binary;
mod analysis;
mod types;
mod lifter;

use binary::PeFile;
use crate::analysis::FunctionDiscovery;
use crate::lifter::IrBuilder;
use tracing::{error, info};
use iced_x86::{Formatter, NasmFormatter};
use crate::lifter::ControlFlowGraph;

fn display_flow_graph(cfg: &ControlFlowGraph, formatter: &mut NasmFormatter) {
    let mut sorted_blocks: Vec<_> = cfg.blocks.iter().collect();
    sorted_blocks.sort_by_key(|(block_id, _)| *block_id);
    
    for (_, block) in sorted_blocks {
        println!("Block {} (0x{:08x} - 0x{:08x})", block.id, block.start_address, block.end_address);
        let mut output = String::new();
        for instruction in &block.instructions {
            output.clear();
            formatter.format(&instruction, &mut output);
            println!("0x{:08x}:  {:<100} ", instruction.ip(), output);
        }
        
        if !block.successors.is_empty() {
            for successor in &block.successors {
                println!("flows to Block {}", successor);
            }
        }
        println!();
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .init();

    let mut pe_file = PeFile::new();
    if let Err(e) = pe_file.load("C:\\Users\\vasie\\Documents\\GitHub\\bin-obfuscator\\testdata\\test.exe") {
        error!("Failed to load PE file: {}", e);
        return;
    }
    info!("PE file loaded");

    let mut formatter = NasmFormatter::new();

    let mut function_discovery = FunctionDiscovery::new(pe_file).unwrap();
    let functions = function_discovery.run().unwrap();
    info!("Discovered {} functions", functions.len());

    let main_function = functions.iter().find(|f| f.start_rva == 0x1100).unwrap();
    let mut ir_builder = IrBuilder::new(main_function.clone());
    
    match ir_builder.build() {
        Ok(()) => {
            let cfg = ir_builder.get_cfg();
            info!("Successfully built CFG with {} basic blocks", cfg.blocks.len());
            
            display_flow_graph(&cfg, &mut formatter);
        }
        Err(e) => {
            error!("Failed to build IR: {}", e);
        }
    }
}