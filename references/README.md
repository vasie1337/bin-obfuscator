# Reference Materials - Usage Guide

This directory contains reference materials for the bin-obfuscator project, organized for efficient LLM/agent consumption.

## Problem Statement

Reference documents can be very large (some 30,000+ tokens), which causes:
- Context window exhaustion
- Loading irrelevant information
- Inefficient retrieval
- Difficulty finding specific techniques

## Solution: Indexed Reference System

### Components

1. **INDEX.json** - Searchable catalog with metadata for all references
2. **query_references.py** - Python tool to search and retrieve references
3. **Original markdown files** - Complete reference documents

## Quick Start

### For LLMs/Agents

**Step 1: Query the index first** (don't load full files blindly)

```python
# Search by keyword
python references/query_references.py search "dispatcher blocks"

# Find by category
python references/query_references.py category control-flow-obfuscation

# Get recommendations for a task
python references/query_references.py task "implement control flow flattening"
```

**Step 2: Get only relevant reference IDs from results**

**Step 3: Load specific files based on need**

```python
# Get full content by reference ID
python references/query_references.py get indirect-control-flow
```

### Command Reference

```bash
# Search by keywords
python query_references.py search "symbolic execution"

# Browse by category
python query_references.py category pe-format

# Find by technique
python query_references.py technique "indirect jumps"

# Get recommendations for a task
python query_references.py task "hide API imports"

# Get full content of a reference
python query_references.py get iat-hiding

# List all references (summary only)
python query_references.py list

# List all categories
python query_references.py categories

# Get summary only (don't show full details)
python query_references.py search "obfuscation" --summary-only
```

## Index Structure

The INDEX.json contains:

```json
{
  "id": "unique-identifier",
  "filename": "actual-file.md",
  "title": "Human readable title",
  "categories": ["control-flow", "obfuscation"],
  "techniques": ["dispatcher blocks", "indirect jumps"],
  "keywords": ["searchable", "terms"],
  "summary": "Brief 2-3 sentence description",
  "use_for": ["when to use this reference"],
  "estimated_tokens": 5500
}
```

## Available Categories

- **control-flow-obfuscation** - Control flow transformation techniques
- **pe-format** - PE file format, loading, manipulation
- **polymorphism** - Polymorphic and metamorphic code
- **deobfuscation** - Analysis and deobfuscation techniques
- **anti-debug** - Anti-debugging and detection
- **virtualization** - VM-based obfuscation
- **assembly** - x86/x64 assembly fundamentals
- **tools** - Tools and frameworks
- **overview** - General overviews

## Best Practices for LLMs/Agents

### ✅ DO

1. **Query index first** - Use query_references.py to find relevant documents
2. **Check token estimates** - Consider estimated_tokens before loading
3. **Use categories** - Browse by category to find related techniques
4. **Read summaries** - Understand what's in a reference before loading it
5. **Load selectively** - Only load references that are directly relevant
6. **Use task recommendations** - Let the tool suggest relevant references

### ❌ DON'T

1. **Don't load all files** - Will exceed context limits
2. **Don't search blindly** - Use the index to guide your search
3. **Don't ignore token counts** - Some files are 30,000+ tokens
4. **Don't skip the index** - It's designed to save time and tokens

## Example Workflows

### Workflow 1: Implementing a new obfuscation technique

```bash
# 1. Search for relevant techniques
python query_references.py task "implement control flow obfuscation"

# 2. Review summaries to understand what each covers
# Output shows: indirect-control-flow, ollvm-enhanced, branch-jump-tables

# 3. Load the most relevant one
python query_references.py get indirect-control-flow > temp_ref.md

# 4. Use the content for implementation
```

### Workflow 2: Understanding a specific concept

```bash
# 1. Search by keyword
python query_references.py search "dispatcher blocks" --summary-only

# 2. Found: indirect-control-flow (5500 tokens)
# Decision: Load it (reasonable size)

# 3. Get content
python query_references.py get indirect-control-flow
```

### Workflow 3: Working with PE files

```bash
# 1. Browse category
python query_references.py category pe-format

# 2. See multiple options:
#    - pe-loader (15000 tokens)
#    - iat-hiding (12000 tokens)
#    - x64-exception-handling (8000 tokens)

# 3. Load smallest/most relevant first
python query_references.py get x64-exception-handling
```

## Token Budget Management

| Reference Size | When to Load |
|---------------|-------------|
| < 5,000 tokens | Load freely |
| 5,000 - 10,000 | Load if highly relevant |
| 10,000 - 20,000 | Only if critical to task |
| > 20,000 tokens | Extract specific sections, don't load whole file |

## Integration with LLM Workflows

### For Claude Code / AI Agents

```python
# In your agent code:
import subprocess
import json

def find_references(query: str) -> list:
    """Query the reference index"""
    result = subprocess.run(
        ['python', 'references/query_references.py', 'search', query],
        capture_output=True, text=True
    )
    return parse_results(result.stdout)

def get_reference(ref_id: str) -> str:
    """Load a specific reference by ID"""
    result = subprocess.run(
        ['python', 'references/query_references.py', 'get', ref_id],
        capture_output=True, text=True
    )
    return result.stdout

# Example usage in agent
def implement_obfuscation_technique(technique: str):
    # Step 1: Find relevant references
    refs = find_references(technique)

    # Step 2: Check token budget
    affordable_refs = [r for r in refs if r['estimated_tokens'] < 10000]

    # Step 3: Load most relevant
    if affordable_refs:
        content = get_reference(affordable_refs[0]['id'])
        # Use content for implementation
```

## Maintenance

### Adding New References

1. Add the markdown file to references/
2. Add an entry to INDEX.json with all metadata
3. Update categories if introducing new ones
4. Estimate token count (rule of thumb: ~4 chars per token)

### Updating the Index

When references change:
1. Update the corresponding entry in INDEX.json
2. Update estimated_tokens if file size changed significantly
3. Update summary/keywords if content changed

## Quick Reference Cards

For common queries, here are the most relevant references:

| Task | References |
|------|-----------|
| Control flow obfuscation | indirect-control-flow, ollvm-enhanced |
| PE file manipulation | ryujin-bin2bin, pe-loader |
| Anti-debugging | anti-debugging |
| IAT hiding | iat-hiding |
| Exception handling | x64-exception-handling, seh-exceptional-behavior |
| Polymorphic code | polymorphic-engine-golang, mutation-engine-aimware |
| VM obfuscation | virtualization-obfuscation |
| Jump tables | branch-jump-tables, jump-tables-hexrays |
| Deobfuscation | symbolic-deobfuscation, defeating-angr |

## Support

If you need to:
- Add new categories → Update INDEX.json categories section
- Search isn't finding something → Check keywords in INDEX.json
- Need a new query type → Extend query_references.py

---

**Remember: Always query the index before loading files. This saves tokens and time!**
