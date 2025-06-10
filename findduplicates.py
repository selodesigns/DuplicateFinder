#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Duplicate Function Finder

A tool to find and report duplicate function definitions across Python files.
Use this script to identify code duplication in your projects.

Author: Sean Elovirta (SELOdev)
Version: 1.0.0
"""
import os
import ast
import hashlib
import argparse
from collections import defaultdict
import sys
from typing import Dict, List, Tuple, Set, Any


class FunctionInfo:
    """Class to store function information including its content, file, and line numbers."""
    def __init__(self, name: str, code: str, file_path: str, start_line: int, end_line: int):
        self.name = name
        self.code = code
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.hash = self._compute_hash()
        
    def _compute_hash(self) -> str:
        """Compute a hash of the function code for comparison."""
        return hashlib.md5(self.code.encode('utf-8')).hexdigest()
    
    def __repr__(self) -> str:
        return f"<Function '{self.name}' in {os.path.basename(self.file_path)}:{self.start_line}-{self.end_line}>"


class FunctionParser(ast.NodeVisitor):
    """AST visitor to extract function definitions from Python files."""
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.functions = []
        
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Get function source code
        start_line = node.lineno - 1  # Convert to 0-indexed
        end_line = node.end_lineno if hasattr(node, 'end_lineno') else self._find_function_end(start_line)
        function_code = '\n'.join(self.source_lines[start_line:end_line])
        
        # Create function info object
        func_info = FunctionInfo(
            name=node.name,
            code=function_code,
            file_path=self.file_path,
            start_line=node.lineno,
            end_line=end_line + 1  # Convert back to 1-indexed for display
        )
        self.functions.append(func_info)
        
        # Continue visiting child nodes (for nested functions)
        self.generic_visit(node)
    
    def _find_function_end(self, start_line: int) -> int:
        """Find the end line of a function when ast.end_lineno is not available."""
        # Simple heuristic: look for the first line with less indentation than the function body
        function_indent = len(self.source_lines[start_line]) - len(self.source_lines[start_line].lstrip())
        for i in range(start_line + 1, len(self.source_lines)):
            if not self.source_lines[i].strip():  # Skip empty lines
                continue
            current_indent = len(self.source_lines[i]) - len(self.source_lines[i].lstrip())
            if current_indent <= function_indent:
                return i - 1
        return len(self.source_lines) - 1


def extract_functions_from_file(file_path: str) -> List[FunctionInfo]:
    """Extract all function definitions from a Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
            source_lines = source.splitlines()
        
        try:
            tree = ast.parse(source)
            parser = FunctionParser(file_path, source_lines)
            parser.visit(tree)
            return parser.functions
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}", file=sys.stderr)
            return []
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
        return []


def find_python_files(directory: str) -> List[str]:
    """Find all Python files in the given directory and its subdirectories."""
    python_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files


def find_duplicate_functions(directory: str, ignore_names: bool = False) -> Dict[str, List[FunctionInfo]]:
    """Find duplicate functions in all Python files in the given directory.
    
    Args:
        directory: The root directory to search for Python files
        ignore_names: If True, functions with different names but identical code will be considered duplicates
        
    Returns:
        A dictionary mapping content hashes to lists of function infos with identical content
    """
    python_files = find_python_files(directory)
    print(f"Found {len(python_files)} Python files")
    
    all_functions = []
    for file_path in python_files:
        functions = extract_functions_from_file(file_path)
        all_functions.extend(functions)
    
    print(f"Found {len(all_functions)} functions")
    
    # Group functions by their hash
    functions_by_hash: Dict[str, List[FunctionInfo]] = defaultdict(list)
    for func in all_functions:
        if ignore_names:
            functions_by_hash[func.hash].append(func)
        else:
            # Use name+hash as key to require both name and content to match for duplication
            functions_by_hash[f"{func.name}:{func.hash}"].append(func)
    
    # Filter out non-duplicates
    duplicates = {k: v for k, v in functions_by_hash.items() if len(v) > 1}
    return duplicates


def format_duplicates_report(duplicates: Dict[str, List[FunctionInfo]]) -> str:
    """Format the duplicate functions as a readable report."""
    if not duplicates:
        return "No duplicate functions found."
    
    report = []
    report.append(f"Found {len(duplicates)} sets of duplicate functions:")
    report.append("\n" + "-" * 80)
    
    for i, (content_hash, functions) in enumerate(duplicates.items(), 1):
        sample_func = functions[0]
        report.append(f"Duplicate #{i}: '{sample_func.name}'")
        report.append(f"Found in {len(functions)} locations:")
        
        for func in functions:
            report.append(f"  - {os.path.relpath(func.file_path)} (lines {func.start_line}-{func.end_line})")
        
        report.append("\nFunction code:")
        report.append("```python")
        report.append(sample_func.code)
        report.append("```")
        report.append("-" * 80)
    
    return "\n".join(report)


def save_report_to_file(report: str, output_path: str, target_dir: str = None) -> None:
    """Save the duplicates report to a file.
    
    Args:
        report: The report content to save
        output_path: The path to save the report to
        target_dir: If provided and output_path is not absolute, join with this directory
    """
    # If output_path is not absolute and target_dir is provided, join them
    if not os.path.isabs(output_path) and target_dir:
        output_path = os.path.join(target_dir, output_path)
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"Report saved to {os.path.abspath(output_path)}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Find duplicate functions in Python files"
    )
    parser.add_argument(
        "directory", 
        help="Directory to scan for Python files",
        default=".",
        nargs="?"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to save the report (defaults to stdout)"
    )
    parser.add_argument(
        "-i", "--ignore-names",
        help="Consider functions with identical code but different names as duplicates",
        action="store_true"
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Print verbose information",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Find duplicate functions
    directory = os.path.abspath(args.directory)
    if args.verbose:
        print(f"Scanning directory: {directory}")
    
    duplicates = find_duplicate_functions(directory, args.ignore_names)
    
    # Generate and output report
    report = format_duplicates_report(duplicates)
    if args.output:
        save_report_to_file(report, args.output, directory)
    else:
        print(report)
    
    # Return statistics
    if duplicates:
        duplicate_count = sum(len(funcs) for funcs in duplicates.values()) - len(duplicates)
        print(f"\nFound {len(duplicates)} unique function(s) with duplicates, {duplicate_count} total duplication(s)")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())