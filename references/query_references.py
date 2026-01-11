#!/usr/bin/env python3
"""
Reference Query Tool for bin-obfuscator
Helps LLMs and agents efficiently navigate reference materials without exceeding context limits.

Usage examples:
    # Search by keyword
    python query_references.py search "dispatcher blocks"

    # Find by category
    python query_references.py category control-flow-obfuscation

    # Find by technique
    python query_references.py technique "symbolic execution"

    # Get summary only (no full content)
    python query_references.py search "PE format" --summary-only

    # Find relevant references for a task
    python query_references.py task "implement control flow flattening"
"""

import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any

class ReferenceQueryTool:
    def __init__(self, index_path: str = None):
        if index_path is None:
            script_dir = Path(__file__).parent
            index_path = script_dir / "INDEX.json"

        with open(index_path, 'r', encoding='utf-8') as f:
            self.index = json.load(f)

        self.references_dir = Path(index_path).parent

    def search_keywords(self, query: str) -> List[Dict[str, Any]]:
        """Search for references matching keywords"""
        query_lower = query.lower()
        results = []

        for ref in self.index['references']:
            score = 0

            # Check in keywords
            if any(query_lower in kw.lower() for kw in ref['keywords']):
                score += 3

            # Check in techniques
            if any(query_lower in tech.lower() for tech in ref['techniques']):
                score += 2

            # Check in title and summary
            if query_lower in ref['title'].lower():
                score += 2
            if query_lower in ref['summary'].lower():
                score += 1

            # Check in categories
            if any(query_lower in cat.lower() for cat in ref['categories']):
                score += 1

            if score > 0:
                results.append({**ref, 'relevance_score': score})

        # Sort by relevance
        results.sort(key=lambda x: x['relevance_score'], reverse=True)
        return results

    def find_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Find references by category"""
        results = []
        for ref in self.index['references']:
            if category in ref['categories'] or any(category.lower() in cat.lower() for cat in ref['categories']):
                results.append(ref)
        return results

    def find_by_technique(self, technique: str) -> List[Dict[str, Any]]:
        """Find references by specific technique"""
        results = []
        technique_lower = technique.lower()
        for ref in self.index['references']:
            if any(technique_lower in tech.lower() for tech in ref['techniques']):
                results.append(ref)
        return results

    def recommend_for_task(self, task_description: str) -> List[Dict[str, Any]]:
        """Recommend references for a specific task"""
        task_lower = task_description.lower()
        results = []

        for ref in self.index['references']:
            score = 0

            # Check use_for field
            if 'use_for' in ref:
                for use_case in ref['use_for']:
                    if any(word in use_case.lower() for word in task_lower.split()):
                        score += 3

            # Check techniques
            if any(word in ' '.join(ref['techniques']).lower() for word in task_lower.split()):
                score += 2

            # Check summary
            if any(word in ref['summary'].lower() for word in task_lower.split() if len(word) > 4):
                score += 1

            if score > 0:
                results.append({**ref, 'relevance_score': score})

        results.sort(key=lambda x: x['relevance_score'], reverse=True)
        return results

    def get_reference_content(self, ref_id: str) -> str:
        """Load full content of a reference by ID"""
        for ref in self.index['references']:
            if ref['id'] == ref_id:
                file_path = self.references_dir / ref['filename']
                if file_path.exists():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        return f.read()
                else:
                    return f"Error: File not found: {file_path}"
        return f"Error: Reference ID '{ref_id}' not found"

    def print_results(self, results: List[Dict[str, Any]], summary_only: bool = False):
        """Pretty print search results"""
        if not results:
            print("No results found.")
            return

        print(f"\nFound {len(results)} result(s):\n")

        for i, ref in enumerate(results, 1):
            print(f"{i}. [{ref['id']}] {ref['title']}")
            print(f"   File: {ref['filename']}")
            print(f"   Categories: {', '.join(ref['categories'])}")
            print(f"   Techniques: {', '.join(ref['techniques'][:5])}", end="")
            if len(ref['techniques']) > 5:
                print(f" (+{len(ref['techniques'])-5} more)")
            else:
                print()

            if 'relevance_score' in ref:
                print(f"   Relevance: {ref['relevance_score']}/10")

            print(f"   Est. tokens: ~{ref['estimated_tokens']:,}")
            print(f"   Summary: {ref['summary'][:150]}...")

            if not summary_only and 'use_for' in ref:
                print(f"   Use for:")
                for use_case in ref['use_for'][:3]:
                    print(f"     • {use_case}")

            print()

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    tool = ReferenceQueryTool()
    command = sys.argv[1].lower()
    summary_only = '--summary-only' in sys.argv

    if command == 'search':
        if len(sys.argv) < 3:
            print("Usage: query_references.py search <query>")
            sys.exit(1)
        query = ' '.join(arg for arg in sys.argv[2:] if not arg.startswith('--'))
        results = tool.search_keywords(query)
        tool.print_results(results, summary_only)

    elif command == 'category':
        if len(sys.argv) < 3:
            print("Usage: query_references.py category <category-name>")
            print("\nAvailable categories:")
            for cat in tool.index['categories'].keys():
                print(f"  • {cat}")
            sys.exit(1)
        category = sys.argv[2]
        results = tool.find_by_category(category)
        tool.print_results(results, summary_only)

    elif command == 'technique':
        if len(sys.argv) < 3:
            print("Usage: query_references.py technique <technique-name>")
            sys.exit(1)
        technique = ' '.join(sys.argv[2:])
        results = tool.find_by_technique(technique)
        tool.print_results(results, summary_only)

    elif command == 'task':
        if len(sys.argv) < 3:
            print("Usage: query_references.py task <task-description>")
            print("\nExample: query_references.py task 'implement control flow flattening'")
            sys.exit(1)
        task = ' '.join(arg for arg in sys.argv[2:] if not arg.startswith('--'))
        results = tool.recommend_for_task(task)
        tool.print_results(results, summary_only)

    elif command == 'get':
        if len(sys.argv) < 3:
            print("Usage: query_references.py get <reference-id>")
            sys.exit(1)
        ref_id = sys.argv[2]
        content = tool.get_reference_content(ref_id)
        print(content)

    elif command == 'list':
        print("All references:\n")
        tool.print_results(tool.index['references'], summary_only=True)

    elif command == 'categories':
        print("Available categories:\n")
        for cat, refs in tool.index['categories'].items():
            print(f"{cat}:")
            print(f"  {len(refs)} reference(s): {', '.join(refs)}")
            print()

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)

if __name__ == '__main__':
    main()
