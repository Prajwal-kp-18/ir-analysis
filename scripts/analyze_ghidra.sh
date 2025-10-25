#!/bin/bash
#
# analyze_ghidra.sh
# Runs Ghidra headless analysis on a single binary and exports P-code IR.
#
# Usage: ./analyze_ghidra.sh <path_to_binary>
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# Path to your Ghidra installation directory (contains support/, Ghidra/, etc.)
# Example: /opt/ghidra_10.4_PUBLIC or /home/user/tools/ghidra_11.0
GHIDRA_INSTALL_DIR="/home/analyst/ghidra"
# Directory where temporary Ghidra projects will be created
# These projects are used for headless analysis and can be cleaned up afterward
GHIDRA_PROJECT_DIR="./ghidra_projects"

# Path to the CFG statistics post-script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
POST_SCRIPT_PATH="$SCRIPT_DIR/get_cfg_stats.py"

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

# Construct path to Ghidra's headless analyzer
HEADLESS_CMD="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"

# Verify that analyzeHeadless exists and is executable
if [ ! -x "$HEADLESS_CMD" ]; then
    echo "ERROR: Ghidra analyzeHeadless not found or not executable at: $HEADLESS_CMD" >&2
    echo "Please check your GHIDRA_INSTALL_DIR setting: $GHIDRA_INSTALL_DIR" >&2
    echo "You can set it via: export GHIDRA_INSTALL_DIR=/path/to/ghidra" >&2
    exit 1
fi

# Verify that the post-script exists
if [ ! -f "$POST_SCRIPT_PATH" ]; then
    echo "ERROR: CFG statistics post-script not found at: $POST_SCRIPT_PATH" >&2
    echo "Please ensure get_cfg_stats.py exists in the scripts directory" >&2
    exit 1
fi

# ============================================================================
# SETUP
# ============================================================================

# Create project directory if it doesn't exist
mkdir -p "$GHIDRA_PROJECT_DIR"

# Generate unique project name based on binary name and timestamp
BINARY_NAME=$(basename "$BINARY_PATH")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PROJECT_NAME="ghidra_analysis_${BINARY_NAME}_${TIMESTAMP}"

echo "=========================================="
echo "Ghidra Headless Analysis"
echo "=========================================="
echo "Binary:  $BINARY_PATH"
echo "Project: $PROJECT_NAME"
echo "Location: $GHIDRA_PROJECT_DIR"
echo "=========================================="

# ============================================================================
# RUN GHIDRA HEADLESS ANALYSIS
# ============================================================================

# Run Ghidra headless analyzer
# Arguments:
#   $GHIDRA_PROJECT_DIR - where to create the project
#   $PROJECT_NAME       - name of the project
#   -import             - import the binary
#   -analysisTimeoutPerFile - timeout in seconds (0 = no timeout)
#   -postScript         - script to run after analysis (extracts CFG stats)
#   -deleteProject      - clean up project after analysis

"$HEADLESS_CMD" \
    "$GHIDRA_PROJECT_DIR" \
    "$PROJECT_NAME" \
    -import "$BINARY_PATH" \
    -analysisTimeoutPerFile 0 \
    -postScript "$POST_SCRIPT_PATH" \
    -deleteProject

# Capture exit status
EXIT_STATUS=$?

# ============================================================================
# ERROR HANDLING
# ============================================================================

if [ $EXIT_STATUS -ne 0 ]; then
    echo "ERROR: Ghidra analysis failed with exit code $EXIT_STATUS" >&2
    exit 1
fi

echo "=========================================="
echo "Ghidra analysis completed successfully"
echo "=========================================="

exit 0
