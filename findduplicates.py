#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Duplicate Function Finder

A tool to find and report duplicate function definitions across Python and C# files.
Use this script to identify code duplication in your projects.

Author: Sean Elovirta (SELOdev)
Version: 1.1.0
"""
import os
import ast
import hashlib
import argparse
import re
from collections import defaultdict
import sys
from typing import Dict, List, Tuple, Set, Any, Optional


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
    """Extract all function definitions from a source file.
    
    Args:
        file_path: Path to the source file
        
    Returns:
        List of FunctionInfo objects representing functions found in the file
    """
    file_ext = os.path.splitext(file_path)[1].lower()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
            source_lines = source.splitlines()
        
        if file_ext == '.py':
            return extract_python_functions(file_path, source, source_lines)
        elif file_ext == '.cs':
            return extract_csharp_functions(file_path, source, source_lines)
        else:
            print(f"Unsupported file type: {file_ext}", file=sys.stderr)
            return []
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
        return []


def extract_python_functions(file_path: str, source: str, source_lines: List[str]) -> List[FunctionInfo]:
    """Extract all function definitions from a Python file."""
    try:
        tree = ast.parse(source)
        parser = FunctionParser(file_path, source_lines)
        parser.visit(tree)
        return parser.functions
    except SyntaxError as e:
        print(f"Syntax error in {file_path}: {e}", file=sys.stderr)
        return []


def extract_csharp_functions(file_path: str, source: str, source_lines: List[str]) -> List[FunctionInfo]:
    """Extract all function/method definitions from a C# file.
    
    This uses regex to find C# function definitions. It's not as robust as a proper parser
    but should work for most common C# function patterns.
    """
    functions = []
    
    # Match C# method declarations
    # This pattern matches common C# method declarations including modifiers, return types, method names and parameters
    method_pattern = r'(?:\s|^)(?:public|private|protected|internal|static|virtual|override|abstract|async|sealed)?(?:\s+(?:public|private|protected|internal|static|virtual|override|abstract|async|sealed))*\s+(?:[A-Za-z0-9_<>\[\]\.,\s]+?)\s+([A-Za-z0-9_]+)\s*\([^\)]*\)\s*(?:{|=>)'    
    
    # Find all method declarations
    for match in re.finditer(method_pattern, source):
        method_name = match.group(1)  # The method name is in the first capture group
        start_pos = match.start()
        
        # Find the line number where this method starts
        start_line = 1
        for i, line in enumerate(source_lines):
            if start_pos <= len(line) + i:  # +i accounts for newline characters
                start_line = i + 1  # Convert to 1-indexed
                break
            start_pos -= len(line) + 1  # +1 for the newline character
        
        # Find the method body and end line
        if '{' in source[match.start():match.start()+100]:  # Check if it's a block body
            # Find matching closing brace
            open_count = 0
            in_string = False
            string_char = None
            end_pos = match.end()
            
            while end_pos < len(source):
                char = source[end_pos]
                
                # Handle string literals to ignore braces inside strings
                if char in '"\'' and (end_pos == 0 or source[end_pos-1] != '\\'):
                    if not in_string:
                        in_string = True
                        string_char = char
                    elif char == string_char:
                        in_string = False
                
                if not in_string:
                    if char == '{':
                        open_count += 1
                    elif char == '}':
                        open_count -= 1
                        if open_count == 0:  # Found the matching closing brace
                            break
                
                end_pos += 1
            
            # Find the line number where the method ends
            end_line = start_line
            chars_counted = 0
            for i, line in enumerate(source_lines[start_line-1:]):
                chars_counted += len(line) + 1  # +1 for newline
                if chars_counted >= (end_pos - match.start()):
                    end_line = start_line + i
                    break
        else:  # It's an expression-bodied member (=>)
            # Find the semicolon at the end
            end_pos = source.find(';', match.end())
            if end_pos == -1:  # No semicolon found
                end_pos = len(source)
                
            # Find the line number where the method ends
            end_line = start_line
            chars_counted = 0
            for i, line in enumerate(source_lines[start_line-1:]):
                chars_counted += len(line) + 1  # +1 for newline
                if chars_counted >= (end_pos - match.start()):
                    end_line = start_line + i
                    break
        
        # Get the method source code
        method_code = '\n'.join(source_lines[start_line-1:end_line])
        
        # Create and add the function info
        func_info = FunctionInfo(
            name=method_name,
            code=method_code,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line
        )
        functions.append(func_info)
    
    return functions


def find_source_files(directory: str, file_types: List[str]) -> Dict[str, List[str]]:
    """Find all files of specified types in the given directory and its subdirectories.
    
    Args:
        directory: The root directory to search for files
        file_types: List of file extensions to find (e.g., ['.py', '.cs'])
        
    Returns:
        A dictionary mapping file types to lists of file paths
    """
    files_by_type = defaultdict(list)
    for root, _, files in os.walk(directory):
        for file in files:
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext in file_types:
                files_by_type[file_ext].append(os.path.join(root, file))
    return files_by_type


def find_duplicate_functions(directory: str, ignore_names: bool = False, file_types: List[str] = ['.py', '.cs']) -> Dict[str, List[FunctionInfo]]:
    """Find duplicate functions in all supported files in the given directory.
    
    Args:
        directory: The root directory to search for files
        ignore_names: If True, functions with different names but identical code will be considered duplicates
        file_types: List of file extensions to search (default: ['.py', '.cs'])
        
    Returns:
        A dictionary mapping content hashes to lists of function infos with identical content
    """
    files_by_type = find_source_files(directory, file_types)
    
    # Print summary of found files
    for file_type, files in files_by_type.items():
        print(f"Found {len(files)} {file_type} files")
    
    all_functions = []
    for file_type, files in files_by_type.items():
        for file_path in files:
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
        # Determine the language based on file extension
        file_ext = os.path.splitext(sample_func.file_path)[1].lower()
        if file_ext == '.py':
            code_lang = "python"
        elif file_ext == '.cs':
            code_lang = "csharp"
        else:
            code_lang = "text"
            
        report.append(f"```{code_lang}")
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
        description="Find duplicate functions in Python and C# files"
    )
    parser.add_argument(
        "directory", 
        help="Directory to scan for Python and C# files",
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
    parser.add_argument(
        "--python-only",
        help="Only scan Python files",
        action="store_true"
    )
    parser.add_argument(
        "--csharp-only",
        help="Only scan C# files",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Find duplicate functions
    directory = os.path.abspath(args.directory)
    if args.verbose:
        print(f"Scanning directory: {directory}")
    
    # Determine which file types to scan
    file_types = []
    if args.python_only:
        file_types = ['.py']
    elif args.csharp_only:
        file_types = ['.cs']
    else:
        file_types = ['.py', '.cs']
    
    duplicates = find_duplicate_functions(directory, args.ignore_names, file_types)
    
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