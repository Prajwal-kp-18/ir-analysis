#!/bin/bash
#
# run_juliet_analysis.sh
# Run IR analysis on Juliet Test Suite dataset
#

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Juliet Test Suite - IR Analysis"
echo "=========================================="

# Activate virtual environment
echo "[1/4] Activating Python environment..."
source .venv/bin/activate

# Load environment variables
echo "[2/4] Loading configuration..."
source .env

# Add RetDec to PATH
export PATH=$PATH:/home/prajwal/tools/llvm-lifters/retdec/bin

# Verify setup
echo "[3/4] Verifying environment..."
echo "  ✓ Python: $(which python3)"
echo "  ✓ angr: $(python3 -c 'import angr; print(angr.__version__)' 2>/dev/null)"
echo "  ✓ Ghidra: $GHIDRA_INSTALL_DIR"
echo "  ✓ Dataset: /home/prajwal/Documents/juliet-test-suite-c/research_dataset"
echo "  ✓ Binaries to analyze: $(ls /home/prajwal/Documents/juliet-test-suite-c/research_dataset | wc -l)"

# Run analysis
echo ""
echo "[4/4] Starting analysis (this will take a while)..."
echo "=========================================="
echo ""

SAMPLES_DIR=/home/prajwal/Documents/juliet-test-suite-c/research_dataset ./scripts/run_all.sh

echo ""
echo "=========================================="
echo "Analysis complete!"
echo "Results saved to: results/"
echo "Generate report with: python3 scripts/report_generator.py"
echo "=========================================="
