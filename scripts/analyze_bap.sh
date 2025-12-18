#!/bin/bash
#
# analyze_bap.sh
# Runs BAP (Binary Analysis Platform) on a single binary and lifts to BIL IR.
#
# Usage: ./analyze_bap.sh <path_to_binary>
#
# Prerequisites:
#   - BAP installed via opam (opam install bap)
#   - bap command available in PATH
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# BAP command - use Docker by default
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BAP_CMD="${BAP_CMD:-${SCRIPT_DIR}/bap_docker.sh}"

# ============================================================================
# INPUT VALIDATION
# ============================================================================

# Check if binary path argument was provided
if [ $# -eq 0 ]; then
    echo "ERROR: No binary path provided" >&2
    echo "Usage: $0 <path_to_binary>" >&2
    exit 1
fi

BINARY_PATH="$1"

# Check if the provided path is a valid file
if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: File not found or not a regular file: $BINARY_PATH" >&2
    exit 1
fi

# ============================================================================
# TOOL AVAILABILITY CHECK
# ============================================================================

# Verify that bap command is available
if [ ! -x "$BAP_CMD" ]; then
    echo "ERROR: BAP command not found or not executable: $BAP_CMD" >&2
    echo "Please ensure Docker is installed:" >&2
    echo "  docker --version" >&2
    echo "And pull the BAP Docker image:" >&2
    echo "  docker pull binaryanalysisplatform/bap:latest" >&2
    exit 1
fi

# ============================================================================
# SETUP
# ============================================================================

BINARY_NAME=$(basename "$BINARY_PATH")

echo "=========================================="
echo "BAP BIL IR Analysis"
echo "=========================================="
echo "Binary:  $BINARY_PATH"
echo "Tool:    $BAP_CMD"
echo "=========================================="

# ============================================================================
# RUN BAP ANALYSIS
# ============================================================================

# Run BAP to lift binary to BIL and print it
# Arguments:
#   -d bil    - disassemble and print BIL (BAP Intermediate Language)
#   The binary path is passed as the last argument
#
# Additional useful BAP options (commented out, can be enabled as needed):
#   -d asm    - print assembly
#   -d bir    - print BIR (BAP Intermediate Representation, higher level)
#   --dump=bir:out.bir - dump BIR to file
#   --passes=<passes> - run specific analysis passes

echo ""
echo "Lifting to BIL IR..."
echo ""

# Run BAP to lift binary to BIL and capture output
echo ""
echo "Lifting to BIL IR..."
echo ""

# Create temporary file for output
BAP_OUT=$(mktemp)

# Use timeout to prevent hanging (default 60 seconds, can be overridden by BAP_TIMEOUT env var)
BAP_TIMEOUT="${BAP_TIMEOUT:-60}"
timeout "${BAP_TIMEOUT}s" "$BAP_CMD" "$BINARY_PATH" -d bil > "$BAP_OUT" 2>&1
EXIT_STATUS=$?

if [ $EXIT_STATUS -eq 0 ]; then
    cat "$BAP_OUT"
    
    # Count metrics using simple heuristics on BIL output
    # Blocks: roughly correspond to scopes enclosed in braces '{' in some output formats, 
    # or we can count jumps as block terminators. 
    # For standard BAP BIL output, it's often a list of statements.
    # Let's count lines with ':=' (assignments), 'jmp', 'call', 'when' as statements.
    # Let's count '{' as block starts if present, otherwise default to 1 or heuristic.
    
    # Note: This is an approximation.
    NUM_STMTS=$(grep -E ":=|jmp|call|when" "$BAP_OUT" | wc -l)
    NUM_BLOCKS=$(grep -c "{" "$BAP_OUT")
    
    # If no blocks detected (flat output), assume at least 1
    if [ "$NUM_BLOCKS" -eq 0 ]; then
        NUM_BLOCKS=1
    fi
    
    echo ""
    echo "--- BAP BIL Stats ---"
    echo "BAP_STATS:Functions=0" # BAP BIL doesn't explicitly list functions in simple output
    echo "BAP_STATS:BasicBlocks=$NUM_BLOCKS"
    echo "BAP_STATS:TotalBilStatements=$NUM_STMTS"
    echo "---------------------"
fi

rm -f "$BAP_OUT"

# ============================================================================
# ERROR HANDLING
# ============================================================================

if [ $EXIT_STATUS -eq 124 ]; then
    echo "" >&2
    echo "ERROR: BAP analysis timed out after ${BAP_TIMEOUT} seconds" >&2
    exit 124
elif [ $EXIT_STATUS -ne 0 ]; then
    echo "" >&2
    echo "ERROR: BAP analysis failed with exit code $EXIT_STATUS" >&2
    exit 1
fi

echo ""
echo "=========================================="
echo "BAP analysis completed successfully"
echo "=========================================="

exit 0
