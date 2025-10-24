#!/bin/bash
#
# run_all.sh
# Orchestrates IR lifting benchmarks across all samples using Ghidra and angr.
# Wraps each analysis with GNU time to capture runtime and memory metrics.
#
# Prerequisites:
#   - GNU time installed (sudo apt install time)
#   - Ghidra installed and GHIDRA_INSTALL_DIR configured
#   - Python virtual environment with angr activated
#
# Usage:
#   1. Activate your angr virtual environment:
#      source /path/to/venv/bin/activate
#   2. Run this script:
#      ./run_all.sh
#   OR set environment variables inline:
#      SAMPLES_DIR=/path/to/samples RESULTS_DIR=/path/to/results ./run_all.sh
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# Directory containing the binary samples to analyze
# Default: samples/benign/ relative to project root
SAMPLES_DIR="${SAMPLES_DIR:-$(dirname "$(dirname "$(readlink -f "$0")")")/samples/benign}"

# Directory where results and logs will be written
# Default: results/ relative to project root
RESULTS_DIR="${RESULTS_DIR:-$(dirname "$(dirname "$(readlink -f "$0")")")/results}"

# Output log file name (will be created in RESULTS_DIR)
OUTPUT_LOG="${OUTPUT_LOG:-analysis_results.log}"

# CSV summary file name (will be created in RESULTS_DIR)
CSV_SUMMARY="${CSV_SUMMARY:-summary.csv}"

# Path to Ghidra installation (required by analyze_ghidra.sh)
# This can also be set as an environment variable before running this script
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"

# ============================================================================
# SCRIPT SETUP
# ============================================================================

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Paths to the analysis scripts
GHIDRA_SCRIPT="$SCRIPT_DIR/analyze_ghidra.sh"
ANGR_SCRIPT="$SCRIPT_DIR/analyze_angr.py"

# Full path to output log and CSV summary
LOG_FILE="$RESULTS_DIR/$OUTPUT_LOG"
CSV_FILE="$RESULTS_DIR/$CSV_SUMMARY"

# ============================================================================
# VALIDATION
# ============================================================================

echo "=========================================="
echo "IR Lifting Benchmark - Batch Analysis"
echo "=========================================="
echo "Samples directory: $SAMPLES_DIR"
echo "Results directory: $RESULTS_DIR"
echo "Output log: $LOG_FILE"
echo "Ghidra install: $GHIDRA_INSTALL_DIR"
echo "=========================================="

# Check if samples directory exists
if [ ! -d "$SAMPLES_DIR" ]; then
    echo "ERROR: Samples directory not found: $SAMPLES_DIR" >&2
    echo "Please create it or set SAMPLES_DIR environment variable" >&2
    exit 1
fi

# Check if there are any files in the samples directory
if [ -z "$(ls -A "$SAMPLES_DIR" 2>/dev/null)" ]; then
    echo "WARNING: Samples directory is empty: $SAMPLES_DIR" >&2
    echo "No binaries to analyze. Exiting." >&2
    exit 0
fi

# Create results directory if it doesn't exist
mkdir -p "$RESULTS_DIR"

# Check if analysis scripts exist
if [ ! -f "$GHIDRA_SCRIPT" ]; then
    echo "ERROR: Ghidra analysis script not found: $GHIDRA_SCRIPT" >&2
    exit 1
fi

if [ ! -f "$ANGR_SCRIPT" ]; then
    echo "ERROR: angr analysis script not found: $ANGR_SCRIPT" >&2
    exit 1
fi

# Check if scripts are executable
if [ ! -x "$GHIDRA_SCRIPT" ]; then
    echo "WARNING: Making Ghidra script executable: $GHIDRA_SCRIPT"
    chmod +x "$GHIDRA_SCRIPT"
fi

if [ ! -x "$ANGR_SCRIPT" ]; then
    echo "WARNING: Making angr script executable: $ANGR_SCRIPT"
    chmod +x "$ANGR_SCRIPT"
fi

# Check if GNU time is available
if ! command -v /usr/bin/time &> /dev/null; then
    echo "ERROR: GNU time not found. Please install it: sudo apt install time" >&2
    exit 1
fi

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found. Please install Python 3.10+" >&2
    exit 1
fi

# Check if angr virtual environment is activated
# Note: This is a best-effort check. Users should activate their venv before running.
if ! python3 -c "import angr" 2>/dev/null; then
    echo "WARNING: angr does not appear to be installed or accessible" >&2
    echo "Please activate your virtual environment with angr installed:" >&2
    echo "  source /path/to/venv/bin/activate" >&2
    echo "Then run this script again." >&2
    exit 1
fi

# Export GHIDRA_INSTALL_DIR for child scripts
export GHIDRA_INSTALL_DIR

# ============================================================================
# INITIALIZE LOG FILE
# ============================================================================

# Clear or create the log file
echo "IR Lifting Benchmark Results" > "$LOG_FILE"
echo "Started: $(date)" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Initialize CSV summary file with headers
echo "sample,tool,elapsed_seconds,max_rss_kb,user_time_seconds,system_time_seconds,status" > "$CSV_FILE"

# ============================================================================
# MAIN ANALYSIS LOOP
# ============================================================================

echo ""
echo "Starting benchmark analysis..."
echo "Results will be written to: $LOG_FILE"
echo ""

# Counter for processed samples
SAMPLE_COUNT=0
SUCCESS_COUNT=0
FAILURE_COUNT=0

# ============================================================================
# HELPER FUNCTION: Parse time output
# ============================================================================

parse_time_output() {
    local time_file="$1"
    local elapsed="N/A"
    local max_rss="N/A"
    local user_time="N/A"
    local sys_time="N/A"
    
    if [ -f "$time_file" ]; then
        # Extract elapsed time (format: h:mm:ss or m:ss.ms)
        elapsed=$(grep "Elapsed (wall clock) time" "$time_file" | awk '{print $NF}' | sed 's/[()]//g')
        
        # Convert elapsed time to seconds
        if [[ "$elapsed" =~ ^([0-9]+):([0-9]+):([0-9.]+)$ ]]; then
            # Format: h:mm:ss.ms
            local hours="${BASH_REMATCH[1]}"
            local minutes="${BASH_REMATCH[2]}"
            local seconds="${BASH_REMATCH[3]}"
            elapsed=$(echo "$hours * 3600 + $minutes * 60 + $seconds" | bc)
        elif [[ "$elapsed" =~ ^([0-9]+):([0-9.]+)$ ]]; then
            # Format: m:ss.ms
            local minutes="${BASH_REMATCH[1]}"
            local seconds="${BASH_REMATCH[2]}"
            elapsed=$(echo "$minutes * 60 + $seconds" | bc)
        fi
        
        # Extract maximum resident set size (in KB)
        max_rss=$(grep "Maximum resident set size" "$time_file" | awk '{print $(NF-1)}')
        
        # Extract user time (in seconds)
        user_time=$(grep "User time (seconds):" "$time_file" | awk '{print $NF}')
        
        # Extract system time (in seconds)
        sys_time=$(grep "System time (seconds):" "$time_file" | awk '{print $NF}')
    fi
    
    echo "$elapsed,$max_rss,$user_time,$sys_time"
}

# Loop through all files in the samples directory
for SAMPLE in "$SAMPLES_DIR"/*; do
    # Skip if not a regular file
    if [ ! -f "$SAMPLE" ]; then
        continue
    fi
    
    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))
    SAMPLE_NAME=$(basename "$SAMPLE")
    
    echo "========================================" | tee -a "$LOG_FILE"
    echo "Processing sample $SAMPLE_COUNT: $SAMPLE_NAME" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
    
    # ------------------------------------------------------------------------
    # Ghidra Analysis
    # ------------------------------------------------------------------------
    
    echo "" | tee -a "$LOG_FILE"
    echo "--- Ghidra P-code Analysis ---" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # Create temporary file for time output
    GHIDRA_TIME_FILE="$RESULTS_DIR/.time_ghidra_${SAMPLE_NAME}_$$.tmp"
    
    # Run Ghidra analysis with time measurement
    # Redirect stdout to log, stderr (time output) to temp file
    if /usr/bin/time -v "$GHIDRA_SCRIPT" "$SAMPLE" 2> "$GHIDRA_TIME_FILE" >> "$LOG_FILE"; then
        echo "Ghidra analysis: SUCCESS" | tee -a "$LOG_FILE"
        GHIDRA_STATUS="success"
    else
        echo "Ghidra analysis: FAILED" | tee -a "$LOG_FILE"
        GHIDRA_STATUS="failed"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
    
    # Append time output to log file
    cat "$GHIDRA_TIME_FILE" >> "$LOG_FILE"
    
    # Parse metrics from time output
    GHIDRA_METRICS=$(parse_time_output "$GHIDRA_TIME_FILE")
    
    # Write to CSV
    echo "$SAMPLE_NAME,ghidra,$GHIDRA_METRICS,$GHIDRA_STATUS" >> "$CSV_FILE"
    
    # Clean up temp file
    rm -f "$GHIDRA_TIME_FILE"
    
    # ------------------------------------------------------------------------
    # angr Analysis
    # ------------------------------------------------------------------------
    
    echo "" | tee -a "$LOG_FILE"
    echo "--- angr VEX IR Analysis ---" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # Create temporary file for time output
    ANGR_TIME_FILE="$RESULTS_DIR/.time_angr_${SAMPLE_NAME}_$$.tmp"
    
    # Run angr analysis with time measurement
    # Redirect stdout to log, stderr (time output) to temp file
    if /usr/bin/time -v python3 "$ANGR_SCRIPT" "$SAMPLE" 2> "$ANGR_TIME_FILE" >> "$LOG_FILE"; then
        echo "angr analysis: SUCCESS" | tee -a "$LOG_FILE"
        ANGR_STATUS="success"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "angr analysis: FAILED" | tee -a "$LOG_FILE"
        ANGR_STATUS="failed"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
    
    # Append time output to log file
    cat "$ANGR_TIME_FILE" >> "$LOG_FILE"
    
    # Parse metrics from time output
    ANGR_METRICS=$(parse_time_output "$ANGR_TIME_FILE")
    
    # Write to CSV
    echo "$SAMPLE_NAME,angr,$ANGR_METRICS,$ANGR_STATUS" >> "$CSV_FILE"
    
    # Clean up temp file
    rm -f "$ANGR_TIME_FILE"
    
    echo "" | tee -a "$LOG_FILE"
    echo "Completed: $SAMPLE_NAME" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
done

# ============================================================================
# SUMMARY
# ============================================================================

echo "========================================" | tee -a "$LOG_FILE"
echo "Benchmark Complete" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Samples processed: $SAMPLE_COUNT" | tee -a "$LOG_FILE"
echo "Successful analyses: $SUCCESS_COUNT" | tee -a "$LOG_FILE"
echo "Failed analyses: $FAILURE_COUNT" | tee -a "$LOG_FILE"
echo "Results saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "CSV summary saved to: $CSV_FILE" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"

# Exit with appropriate status
if [ $FAILURE_COUNT -gt 0 ]; then
    exit 1
else
    exit 0
fi
