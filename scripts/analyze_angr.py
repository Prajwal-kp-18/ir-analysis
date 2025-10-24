#!/usr/bin/env python3
"""
analyze_angr.py
Runs angr analysis on a single binary to lift it to VEX IR.

Usage: python3 analyze_angr.py <path_to_binary>

Prerequisites:
    - Python 3.10+
    - angr installed (pip install angr)
    - Recommended: Run within a virtual environment with angr installed
"""

import sys
import os


def analyze_binary(binary_path):
    """
    Load a binary with angr and perform basic IR lifting analysis.
    
    Args:
        binary_path: Path to the binary file to analyze
        
    Returns:
        None (prints analysis results to stdout)
    """
    try:
        # Import angr here to provide a clearer error if it's not installed
        import angr
    except ImportError as e:
        print("ERROR: angr is not installed or not accessible", file=sys.stderr)
        print("Please install angr: pip install angr", file=sys.stderr)
        print(f"Import error details: {e}", file=sys.stderr)
        sys.exit(1)
    
    print("=" * 50)
    print("angr VEX IR Analysis")
    print("=" * 50)
    print(f"Binary: {binary_path}")
    print("=" * 50)
    
    try:
        # Load the binary with angr
        # This automatically lifts the binary to VEX IR
        print("Loading binary with angr...")
        project = angr.Project(binary_path, auto_load_libs=False)
        
        print(f"Architecture: {project.arch.name}")
        print(f"Entry point: {hex(project.entry)}")
        print(f"Binary base address: {hex(project.loader.main_object.min_addr)}")
        
        # Get the Control Flow Graph (CFG) - this triggers IR lifting
        print("\nGenerating CFG (this will lift code to VEX IR)...")
        cfg = project.analyses.CFGFast()
        
        # Count functions discovered
        function_count = len(cfg.functions)
        print(f"Functions discovered: {function_count}")
        
        # Count basic blocks
        node_count = len(cfg.graph.nodes())
        print(f"Basic blocks (CFG nodes): {node_count}")
        
        # Optional: Show some function names
        if function_count > 0:
            print("\nSample functions (first 10):")
            for i, (addr, func) in enumerate(list(cfg.functions.items())[:10]):
                func_name = func.name if func.name else f"sub_{hex(addr)}"
                print(f"  - {func_name} @ {hex(addr)}")
        
        print("=" * 50)
        print("angr analysis completed successfully")
        print("=" * 50)
        
    except Exception as e:
        print(f"ERROR: angr analysis failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for the script."""
    
    # ========================================================================
    # INPUT VALIDATION
    # ========================================================================
    
    # Check if binary path argument was provided
    if len(sys.argv) != 2:
        print("ERROR: Invalid number of arguments", file=sys.stderr)
        print(f"Usage: {sys.argv[0]} <path_to_binary>", file=sys.stderr)
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    # Check if the file exists
    if not os.path.exists(binary_path):
        print(f"ERROR: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)
    
    # Check if it's a regular file
    if not os.path.isfile(binary_path):
        print(f"ERROR: Not a regular file: {binary_path}", file=sys.stderr)
        sys.exit(1)
    
    # ========================================================================
    # RUN ANALYSIS
    # ========================================================================
    
    analyze_binary(binary_path)
    
    # Exit cleanly on success
    sys.exit(0)


if __name__ == "__main__":
    main()
