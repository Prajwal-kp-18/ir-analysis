#!/bin/bash
#
# activate.sh
# Quick activation script for IR Lifting Benchmark environment
# 
# Usage: source ./activate.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate Python virtual environment
if [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
    echo "✓ Python virtual environment activated"
else
    echo "ERROR: Virtual environment not found at $SCRIPT_DIR/.venv"
    return 1
fi

# Load environment variables
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
    echo "✓ Environment variables loaded"
else
    echo "WARNING: .env file not found at $SCRIPT_DIR/.env"
fi

# Verify setup
echo ""
echo "=== Environment Status ==="
echo "Working directory: $SCRIPT_DIR"
echo "Python: $(which python3)"
echo "angr: $(python3 -c 'import angr; print(angr.__version__)' 2>/dev/null || echo 'NOT FOUND')"
echo "Ghidra: ${GHIDRA_INSTALL_DIR:-NOT SET}"
echo "RetDec: $(which retdec-decompiler 2>/dev/null || echo 'not in PATH')"
echo "BAP enabled: ${ENABLE_BAP:-false}"
echo "LLVM enabled: ${ENABLE_LLVM:-false}"
echo ""
echo "Ready to analyze! Run: ./scripts/run_all.sh"
echo "For test run:         SAMPLES_DIR=samples/benign ./scripts/run_all.sh"
echo ""
