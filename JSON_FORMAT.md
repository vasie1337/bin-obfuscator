# Basic Block JSON Export Format

This document describes the JSON format used to export basic block analysis for visualization tools.

## Usage

```bash
cargo run --package cli -- <binary.exe> --export-json
```

This will create a `<binary>_obfuscated.json` file in the same directory.

## JSON Structure

### Root Object

```json
{
  "binary_name": "example.exe",
  "functions": [...],
  "summary": {...}
}
```

### Function Object

Each function in the `functions` array contains:

```json
{
  "rva": "0x00001000",
  "size": 256,
  "source": "CallTarget",
  "blocks": [...],
  "edges": [...],
  "stats": {...}
}
```

- `rva`: Relative Virtual Address of the function (hex string)
- `size`: Size of the function in bytes
- `source`: How the function was discovered (`CallTarget`, `EntryPoint`, `Export`, etc.)
- `blocks`: Array of basic blocks in this function
- `edges`: Array of control flow edges between blocks
- `stats`: Statistics about the function

### Basic Block Object

```json
{
  "id": "00001000",
  "start_rva": "0x00001000",
  "end_rva": "0x00001008",
  "size": 9,
  "terminator": "ConditionalJump { target: Some(4112), fallthrough: 4105 }",
  "bytes": "4885c07405e9..."
}
```

- `id`: Block identifier (RVA without 0x prefix, for easier referencing)
- `start_rva`: Starting address of the block
- `end_rva`: Ending address of the block (inclusive)
- `size`: Size in bytes
- `terminator`: Type of instruction that ends the block
- `bytes`: Hex-encoded bytes of the block

### Edge Object

```json
{
  "from": "00001000",
  "to": "00001010",
  "edge_type": "conditional_taken"
}
```

- `from`: Source block ID
- `to`: Target block ID
- `edge_type`: Type of control flow edge
  - `unconditional`: Direct jump
  - `conditional_taken`: Conditional branch (taken path)
  - `conditional_fallthrough`: Conditional branch (fall-through path)
  - `call`: Function call
  - `other`: Other types

### Block Terminator Types

- `UnconditionalJump { target: Option<u32> }`: Direct jump
- `ConditionalJump { target: Option<u32>, fallthrough: u32 }`: Conditional branch
- `Return`: Function return
- `Call { target: Option<u32>, fallthrough: u32 }`: Function call
- `IndirectJump`: Register/memory-based jump (target unknown)
- `Interrupt`: System interrupt
- `EndOfFunction`: End of function code

### Function Stats Object

```json
{
  "total_blocks": 15,
  "total_instructions": 47,
  "return_blocks": 2,
  "has_loops": true
}
```

- `total_blocks`: Number of basic blocks in function
- `total_instructions`: Total instruction count
- `return_blocks`: Number of blocks ending with return
- `has_loops`: Whether function contains loops (back-edges)

### Summary Object

```json
{
  "total_functions": 242,
  "total_blocks": 1823,
  "total_instructions": 3478,
  "avg_blocks_per_function": 7.53
}
```

## Visualization Tools

This format is designed to be easily consumed by:

- Graph visualization libraries (D3.js, Cytoscape.js, Graphviz)
- Custom analysis tools
- Static analyzers
- IDA Pro/Ghidra scripts

## Example: Simple Function

```json
{
  "rva": "0x00001000",
  "size": 32,
  "source": "CallTarget",
  "blocks": [
    {
      "id": "00001000",
      "start_rva": "0x00001000",
      "end_rva": "0x00001007",
      "size": 8,
      "terminator": "ConditionalJump { target: Some(4112), fallthrough: 4104 }",
      "bytes": "4885c07405"
    },
    {
      "id": "00001008",
      "start_rva": "0x00001008",
      "end_rva": "0x0000100F",
      "size": 8,
      "terminator": "Return",
      "bytes": "b801000000c3"
    },
    {
      "id": "00001010",
      "start_rva": "0x00001010",
      "end_rva": "0x00001017",
      "size": 8,
      "terminator": "Return",
      "bytes": "b802000000c3"
    }
  ],
  "edges": [
    {
      "from": "00001000",
      "to": "00001010",
      "edge_type": "conditional_taken"
    },
    {
      "from": "00001000",
      "to": "00001008",
      "edge_type": "conditional_fallthrough"
    }
  ],
  "stats": {
    "total_blocks": 3,
    "total_instructions": 6,
    "return_blocks": 2,
    "has_loops": false
  }
}
```

This represents a simple if-else function with two return paths.
