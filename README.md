# Binary Obfuscator

A x86-64 PE binary obfuscation tool that transforms executable code to make reverse engineering more difficult while preserving functionality.

## Overview

This tool analyzes PE binaries with their corresponding PDB debug files and applies various obfuscation techniques to the machine code. The obfuscation process focuses on instruction-level mutations that maintain program semantics while increasing complexity.

## Architecture

The project consists of three main crates:

- `core` - Contains the core obfuscation engine, analysis, and compilation logic
- `cli` - Command-line interface for the obfuscator
- `common` - Shared utilities and logging functionality

## Features

### Instruction Mutations

The mutation pass transforms specific x86-64 instructions into functionally equivalent but more complex sequences:

- **LEA mutations** - Adds random displacement with compensating SUB instruction
- **ADD mutations** - Replaces with CLC + ADC + flag preservation
- **OR mutations** - Replaces with complex bit manipulation using ANDN, BLSI, TZCNT
- **INC/DEC mutations** - Replaces with CLC + ADC/SBB + flag preservation
- **PUSH mutations** - Replaces with explicit memory operations (MOV + SUB)

### Analysis Engine

- PE binary parsing and validation
- PDB debug information processing
- Function discovery from debug symbols
- Multi-stage filtering pipeline:
  - Size filtering (removes functions ≤5 bytes)
  - Exception function filtering (skips functions with unwind handlers)
  - Instruction decoding validation

### Branch Management

- Branch instruction detection and mapping
- Internal branch target tracking and fixup
- Support for conditional and unconditional branches
- Cross-reference resolution after mutation

### Compilation System

- Binary reconstruction with obfuscated code
- Instruction re-encoding and optimization
- Output generation preserving PE structure

## Mutation Stability

**Warning: The mutation system is experimental and unstable.**

Current limitations:

- Flag register handling may not preserve all semantics
- Complex control flow may break with certain mutations
- Memory operand mutations need validation
- Some instruction sequences may produce incorrect results
- Functions with indirect jumps or jump tables are not supported
- Exception handling functions are automatically skipped

The mutation pass transforms instructions but proper testing is required for each target binary.

## Usage

```bash
bin-obfuscator <BINARY_PATH> <PDB_PATH> [OPTIONS]

Arguments:
  <BINARY_PATH>  Path to the PE binary file to obfuscate
  <PDB_PATH>     Path to the corresponding PDB debug file

Options:
  -o, --output <OUTPUT_PATH>  Output path for the obfuscated binary
  -v, --verbose              Enable verbose output (use -vv for debug, -vvv for trace)
  -q, --quiet                Suppress non-error output
  -h, --help                 Print help
```

## Requirements

- x86-64 PE executable files (.exe, .dll)
- Corresponding PDB debug files
- Windows target platform

## Dependencies

- `iced-x86` - x86 instruction encoding/decoding
- `goblin` - Binary parsing
- `symbolic` - Debug symbol processing
- `clap` - CLI argument parsing
- `rand` - Random number generation for mutations

## Build

```bash
cargo build --release
```

## Example

```bash
bin-obfuscator.exe target.exe target.pdb -o obfuscated.exe -v
```

This will obfuscate `target.exe` using debug information from `target.pdb` and output the result to `obfuscated.exe` with verbose logging.
