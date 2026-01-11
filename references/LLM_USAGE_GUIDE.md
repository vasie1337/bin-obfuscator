# LLM/Agent Usage Guide for References

This guide shows how LLMs and AI agents should interact with the reference system.

## Core Principle

**Never load reference files directly. Always query the index first.**

## Step-by-Step Process

### Step 1: Understand Your Task

Before searching, identify:
- What are you trying to implement?
- What specific technique do you need?
- What problem are you solving?

### Step 2: Query the Index

Use the query tool to find relevant references:

```bash
# For implementation tasks
python references/query_references.py task "your task description"

# For concept understanding
python references/query_references.py search "specific concept"

# For browsing a category
python references/query_references.py category "category-name"
```

### Step 3: Evaluate Results

Check the output for:
- **Relevance score** - Higher is better
- **Estimated tokens** - Will it fit in context?
- **Summary** - Does this actually cover what you need?
- **Use cases** - Matches your task?

### Step 4: Make Loading Decisions

```
Token Budget Decision Matrix:

Task Criticality:   Low         Medium      High
< 5k tokens:       Load        Load        Load
5-10k tokens:      Skip        Load        Load
10-20k tokens:     Skip        Maybe       Load
> 20k tokens:      Skip        Skip        Extract sections
```

### Step 5: Load Selectively

Only load what you need:

```bash
# Load full reference (if under token budget)
python references/query_references.py get <ref-id>

# Get summary only
python references/query_references.py search "term" --summary-only
```

## Example: Implementing Dispatcher Blocks

```bash
# ❌ WRONG: Load files blindly
# cat references/Obfuscation*.md  (wastes tokens)

# ✅ CORRECT: Query first
$ python references/query_references.py search "dispatcher blocks"

Found 2 result(s):

1. [indirect-control-flow] LummaC2: Obfuscation Through Indirect Control Flow
   Categories: control-flow-obfuscation, deobfuscation, malware-analysis
   Techniques: dispatcher blocks, indirect jumps, control flow flattening
   Relevance: 6/10
   Est. tokens: ~5,500
   Summary: Detailed analysis of LummaC2's control flow obfuscation using...
   Use for:
     • implementing dispatcher-based control flow obfuscation
     • understanding how to hide control flow with indirect jumps
     • designing resilient obfuscation against static analysis

2. [technical-challenges-indirect-cf] Technical Challenges of Indirect Control Flow
   Categories: control-flow, analysis, challenges
   Relevance: 3/10
   Est. tokens: ~7,000

# Decision: Load the first one (5.5k tokens, high relevance)
$ python references/query_references.py get indirect-control-flow > dispatcher_ref.md
```

## Example: Working with PE Files

```bash
# Task: Need to understand PE sections for obfuscation

# Step 1: Query by category
$ python references/query_references.py category pe-format

Found 7 result(s):

1. [ryujin-bin2bin] Ryūjin - Writing a Bin2Bin Obfuscator
   Est. tokens: ~47,000  ⚠️ TOO LARGE

2. [pe-loader] Writing a Local PE Loader from Scratch
   Est. tokens: ~15,000  ⚠️ LARGE

3. [x64-exception-handling] x64 Exception Handling
   Est. tokens: ~8,000   ✓ REASONABLE

# Decision: Start with smallest relevant reference
$ python references/query_references.py get x64-exception-handling

# If need more info later, load pe-loader
# Skip ryujin-bin2bin unless absolutely critical
```

## Example: Learning a Technique

```bash
# Task: Understand polymorphic code generation

# Step 1: Query by technique
$ python references/query_references.py technique "polymorphic"

Found 3 result(s):

1. [polymorphic-engine-golang] Writing a Polymorphic Engine in Golang
   Est. tokens: ~8,000
   Use for:
     • implementing polymorphic code generation
     • understanding instruction substitution

2. [mutation-engine-aimware] Writing a Mutation Engine
   Est. tokens: ~10,000

3. [polymorphic-engine-improvements] Improving Polymorphic Engine
   Est. tokens: ~8,000

# Decision: Load #1 (most fundamental, 8k tokens)
$ python references/query_references.py get polymorphic-engine-golang
```

## Token Management Strategies

### Strategy 1: Load Progressive

Start small, load more if needed:

```bash
# 1. Get summaries first
python query_references.py search "control flow" --summary-only

# 2. Load smallest relevant reference
python query_references.py get <smallest-ref-id>

# 3. If insufficient, load next one
```

### Strategy 2: Task-Specific Loading

Load only for current sub-task:

```
If task = "Implement control flow + IAT hiding":
  Sub-task 1: Control flow
    → Load control-flow references
    → Implement
    → Clear context if needed

  Sub-task 2: IAT hiding
    → Load IAT references
    → Implement
```

### Strategy 3: Summary + Targeted Loading

```bash
# 1. Get all summaries
python query_references.py list

# 2. Identify the ONE most critical reference
# 3. Load only that one
# 4. Implement based on that
# 5. Come back for more if needed
```

## Common Pitfalls

### ❌ DON'T DO THIS

```bash
# Loading multiple large files
cat references/*.md  # 200,000+ tokens!

# Loading without checking size
cat references/Ryūjin*.md  # 47,000 tokens!

# Searching the raw files
grep -r "dispatcher" references/  # Inefficient
```

### ✅ DO THIS

```bash
# Query the index
python query_references.py search "dispatcher"

# Check token estimates
python query_references.py search "dispatcher" --summary-only

# Load selectively
python query_references.py get indirect-control-flow
```

## Integration Patterns

### Pattern 1: Python Integration

```python
import subprocess
import json

class ReferenceManager:
    def search(self, query: str):
        result = subprocess.run(
            ['python', 'references/query_references.py', 'search', query, '--summary-only'],
            capture_output=True, text=True
        )
        return result.stdout

    def load_if_needed(self, ref_id: str, max_tokens: int = 10000):
        # Check size first from index
        with open('references/INDEX.json') as f:
            index = json.load(f)

        ref = next((r for r in index['references'] if r['id'] == ref_id), None)

        if ref and ref['estimated_tokens'] <= max_tokens:
            result = subprocess.run(
                ['python', 'references/query_references.py', 'get', ref_id],
                capture_output=True, text=True
            )
            return result.stdout
        else:
            return f"Reference too large ({ref['estimated_tokens']} tokens)"

# Usage
rm = ReferenceManager()
refs = rm.search("control flow obfuscation")
print(refs)

content = rm.load_if_needed("indirect-control-flow", max_tokens=10000)
```

### Pattern 2: Context-Aware Loading

```python
def implement_feature(feature_name: str, available_tokens: int):
    """Implement a feature with token budget awareness"""

    # 1. Search for references
    refs = search_references(feature_name)

    # 2. Calculate how many we can load
    budget = available_tokens * 0.3  # Reserve 30% for references

    # 3. Load highest-relevance refs that fit budget
    loaded_refs = []
    used_tokens = 0

    for ref in sorted(refs, key=lambda r: r['relevance_score'], reverse=True):
        if used_tokens + ref['estimated_tokens'] <= budget:
            content = load_reference(ref['id'])
            loaded_refs.append(content)
            used_tokens += ref['estimated_tokens']
        else:
            break

    # 4. Implement using loaded references
    return implement_with_refs(loaded_refs)
```

### Pattern 3: Two-Pass Approach

```python
def research_then_implement(task: str):
    """Research phase, then implementation phase"""

    # Pass 1: Research (load references)
    print("=== RESEARCH PHASE ===")
    refs = search_references(task)
    print(f"Found {len(refs)} references")

    # Load only summaries
    summaries = [get_summary(ref) for ref in refs[:3]]
    design = create_design_from_summaries(summaries)

    # Clear context / start fresh
    print("\n=== IMPLEMENTATION PHASE ===")

    # Pass 2: Implementation (load detailed reference if needed)
    if need_more_detail():
        detailed_ref = load_reference(refs[0]['id'])
        implement(design, detailed_ref)
    else:
        implement(design)
```

## Cheat Sheet

```bash
# Quick reference for common tasks

# 1. Starting a new feature
python query_references.py task "feature description"

# 2. Understanding a concept
python query_references.py search "concept name"

# 3. Browsing techniques
python query_references.py categories

# 4. Loading reference
python query_references.py get <ref-id>

# 5. Summary only
python query_references.py search "term" --summary-only
```

## Best Practices Summary

1. ✅ **Always query index first**
2. ✅ **Check token estimates before loading**
3. ✅ **Load smallest relevant reference**
4. ✅ **Use --summary-only when exploring**
5. ✅ **Budget 30-40% of context for references**
6. ❌ **Never load files directly without querying**
7. ❌ **Never load multiple large (>10k) references**
8. ❌ **Never load references "just in case"**

---

**Remember: The index is your friend. Use it!**
