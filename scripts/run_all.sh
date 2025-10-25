#!/bin/bash
#
# run_all.sh
# Orchestrates IR lifting benchmarks across all samples using Ghidra, angr, BAP, and LLVM.
# Wraps each analysis with GNU time to capture runtime and memory metrics.
#
# Prerequisites:
#   - GNU time installed (sudo apt install time)
#   - Ghidra installed and GHIDRA_INSTALL_DIR configured
#   - Python virtual environment with angr activated
#   - BAP installed via opam (optional, set ENABLE_BAP=true to enable)
#   - LLVM toolchain installed (optional, set ENABLE_LLVM=true to enable)
#
# Usage:
#   1. Activate your angr virtual environment:
#      source /path/to/venv/bin/activate
#   2. Run this script:
#      ./run_all.sh
#   OR set environment variables inline:
#      SAMPLES_DIR=/path/to/samples RESULTS_DIR=/path/to/results ./run_all.sh
#      ENABLE_BAP=true ENABLE_LLVM=true ./run_all.sh  # Enable optional tools
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# Directory containing the binary samples to analyze
# Default: samples/benign/ relative to project root
SAMPLES_DIR="${SAMPLES_DIR:-$(dirname "$(dirname "$(readlink -f "$0")")")/samples/malware}"

# Directory where results and logs will be written
# Default: results/ relative to project root
RESULTS_DIR="${RESULTS_DIR:-$(dirname "$(dirname "$(readlink -f "$0")")")/results}"

# Output log file name (will be created in RESULTS_DIR)
OUTPUT_LOG="${OUTPUT_LOG:-analysis_results.log}"

# CSV summary file name (will be created in RESULTS_DIR)
CSV_SUMMARY="${CSV_SUMMARY:-summary.csv}"

# Path to Ghidra installation (required by analyze_ghidra.sh)
# This can also be set as an environment variable before running this script
GHIDRA_INSTALL_DIR="/home/analyst/ghidra"

# Enable BAP analysis (set to "true" to enable, "false" or empty to disable)
# BAP must be installed via opam for this to work
ENABLE_BAP="${ENABLE_BAP:-false}"

# Enable LLVM analysis (set to "true" to enable, "false" or empty to disable)
# LLVM toolchain must be installed for this to work
ENABLE_LLVM="${ENABLE_LLVM:-false}"
# ============================================================================
# SCRIPT SETUP
# ============================================================================

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Paths to the analysis scripts
GHIDRA_SCRIPT="$SCRIPT_DIR/analyze_ghidra.sh"
ANGR_SCRIPT="$SCRIPT_DIR/analyze_angr.py"
BAP_SCRIPT="$SCRIPT_DIR/analyze_bap.sh"
LLVM_SCRIPT="$SCRIPT_DIR/analyze_llvm.sh"

# Full path to output log and CSV summary
LOG_FILE="$RESULTS_DIR/$OUTPUT_LOG"

# ============================================================================
# VALIDATION
# ============================================================================

echo "========================================="
echo "IR Lifting Benchmark - Batch Analysis"
echo "========================================="
echo "Samples directory: $SAMPLES_DIR"
echo "Results directory: $RESULTS_DIR"
echo "Output log: $LOG_FILE"
echo "Ghidra install: $GHIDRA_INSTALL_DIR"
echo "BAP enabled: $ENABLE_BAP"
echo "LLVM enabled: $ENABLE_LLVM"
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

if [ "$ENABLE_BAP" = "true" ] && [ ! -f "$BAP_SCRIPT" ]; then
    echo "ERROR: BAP analysis script not found: $BAP_SCRIPT" >&2
    exit 1
fi

if [ "$ENABLE_LLVM" = "true" ] && [ ! -f "$LLVM_SCRIPT" ]; then
    echo "ERROR: LLVM analysis script not found: $LLVM_SCRIPT" >&2
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

if [ "$ENABLE_BAP" = "true" ] && [ ! -x "$BAP_SCRIPT" ]; then
    echo "WARNING: Making BAP script executable: $BAP_SCRIPT"
    chmod +x "$BAP_SCRIPT"
fi

if [ "$ENABLE_LLVM" = "true" ] && [ ! -x "$LLVM_SCRIPT" ]; then
    echo "WARNING: Making LLVM script executable: $LLVM_SCRIPT"
    chmod +x "$LLVM_SCRIPT"
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

# Check if BAP is available (if enabled)
if [ "$ENABLE_BAP" = "true" ]; then
    if ! command -v bap &> /dev/null; then
        echo "WARNING: BAP is enabled but 'bap' command not found" >&2
        echo "Please install BAP via opam:" >&2
        echo "  1. sudo apt install opam" >&2
        echo "  2. opam init" >&2
        echo "  3. opam install bap" >&2
        echo "Or disable BAP by setting ENABLE_BAP=false" >&2
        exit 1
    fi
fi

# Check if LLVM is available (if enabled)
if [ "$ENABLE_LLVM" = "true" ]; then
    LLVM_FOUND=false
    if command -v llvm-objdump &> /dev/null || command -v llvm-dis &> /dev/null; then
        LLVM_FOUND=true
    fi
    
    if [ "$LLVM_FOUND" = false ]; then
        echo "WARNING: LLVM is enabled but no LLVM tools found" >&2
        echo "Please install LLVM toolchain:" >&2
        echo "  sudo apt install llvm" >&2
        echo "Or disable LLVM by setting ENABLE_LLVM=false" >&2
        exit 1
    fi
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
    
    # Create temporary files for time output and stdout
    GHIDRA_TIME_FILE="$RESULTS_DIR/.time_ghidra_${SAMPLE_NAME}_$$.tmp"
    GHIDRA_STDOUT_FILE="$RESULTS_DIR/.stdout_ghidra_${SAMPLE_NAME}_$$.tmp"
    
    # Run Ghidra analysis with time measurement
    # Redirect stdout to temp file, stderr (time output) to time file
    if /usr/bin/time -v "$GHIDRA_SCRIPT" "$SAMPLE" > "$GHIDRA_STDOUT_FILE" 2> "$GHIDRA_TIME_FILE"; then
        echo "Ghidra analysis: SUCCESS" | tee -a "$LOG_FILE"
        GHIDRA_STATUS="success"
    else
        echo "Ghidra analysis: FAILED" | tee -a "$LOG_FILE"
        GHIDRA_STATUS="failed"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
    
    # Append stdout to log file
    cat "$GHIDRA_STDOUT_FILE" >> "$LOG_FILE"
    
    # Extract and log CFG statistics
    echo "" >> "$LOG_FILE"
    echo "Ghidra CFG Stats:" >> "$LOG_FILE"
    grep "GHIDRA_STATS:" "$GHIDRA_STDOUT_FILE" >> "$LOG_FILE" 2>/dev/null || echo "  (CFG stats not available)" >> "$LOG_FILE"
    
    # Extract and log performance metrics
    echo "" >> "$LOG_FILE"
    echo "Ghidra Performance:" >> "$LOG_FILE"
    grep -E 'Elapsed \(wall clock\) time|Maximum resident set size' "$GHIDRA_TIME_FILE" >> "$LOG_FILE"
    
    # Parse metrics from time output
    GHIDRA_METRICS=$(parse_time_output "$GHIDRA_TIME_FILE")
    
    # Write to CSV
    echo "$SAMPLE_NAME,ghidra,$GHIDRA_METRICS,$GHIDRA_STATUS" >> "$CSV_FILE"
    
    # Clean up temp files
    rm -f "$GHIDRA_TIME_FILE" "$GHIDRA_STDOUT_FILE"
    
    # ------------------------------------------------------------------------
    # angr Analysis
    # ------------------------------------------------------------------------
    
    echo "" | tee -a "$LOG_FILE"
    echo "--- angr VEX IR Analysis ---" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # Create temporary files for time output and stdout
    ANGR_TIME_FILE="$RESULTS_DIR/.time_angr_${SAMPLE_NAME}_$$.tmp"
    ANGR_STDOUT_FILE="$RESULTS_DIR/.stdout_angr_${SAMPLE_NAME}_$$.tmp"
    
    # Run angr analysis with time measurement
    # Redirect stdout to temp file, stderr (time output) to time file
    if /usr/bin/time -v python3 "$ANGR_SCRIPT" "$SAMPLE" > "$ANGR_STDOUT_FILE" 2> "$ANGR_TIME_FILE"; then
        echo "angr analysis: SUCCESS" | tee -a "$LOG_FILE"
        ANGR_STATUS="success"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "angr analysis: FAILED" | tee -a "$LOG_FILE"
        ANGR_STATUS="failed"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
    
    # Append stdout to log file
    cat "$ANGR_STDOUT_FILE" >> "$LOG_FILE"
    
    # Extract and log CFG statistics
    echo "" >> "$LOG_FILE"
    echo "angr CFG Stats:" >> "$LOG_FILE"
    grep "ANGR_STATS:" "$ANGR_STDOUT_FILE" >> "$LOG_FILE" 2>/dev/null || echo "  (CFG stats not available)" >> "$LOG_FILE"
    
    # Extract and log performance metrics
    echo "" >> "$LOG_FILE"
    echo "angr Performance:" >> "$LOG_FILE"
    grep -E 'Elapsed \(wall clock\) time|Maximum resident set size' "$ANGR_TIME_FILE" >> "$LOG_FILE"
    
    # Parse metrics from time output
    ANGR_METRICS=$(parse_time_output "$ANGR_TIME_FILE")
    
    # Write to CSV
    echo "$SAMPLE_NAME,angr,$ANGR_METRICS,$ANGR_STATUS" >> "$CSV_FILE"
    
    # Clean up temp files
    rm -f "$ANGR_TIME_FILE" "$ANGR_STDOUT_FILE"
    
    # ------------------------------------------------------------------------
    # BAP Analysis (if enabled)
    # ------------------------------------------------------------------------
    
    if [ "$ENABLE_BAP" = "true" ]; then
        echo "" | tee -a "$LOG_FILE"
        echo "--- BAP BIL IR Analysis ---" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        
        # Create temporary file for time output
        BAP_TIME_FILE="$RESULTS_DIR/.time_bap_${SAMPLE_NAME}_$$.tmp"
        
        # Run BAP analysis with time measurement
        # Redirect stdout to log, stderr (time output) to temp file
        if /usr/bin/time -v "$BAP_SCRIPT" "$SAMPLE" 2> "$BAP_TIME_FILE" >> "$LOG_FILE"; then
            echo "BAP analysis: SUCCESS" | tee -a "$LOG_FILE"
            BAP_STATUS="success"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            echo "BAP analysis: FAILED" | tee -a "$LOG_FILE"
            BAP_STATUS="failed"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        fi
        
        # Append time output to log file
        cat "$BAP_TIME_FILE" >> "$LOG_FILE"
        
        # Parse metrics from time output
        BAP_METRICS=$(parse_time_output "$BAP_TIME_FILE")
        
        # Write to CSV
        echo "$SAMPLE_NAME,bap,$BAP_METRICS,$BAP_STATUS" >> "$CSV_FILE"
        
        # Clean up temp file
        rm -f "$BAP_TIME_FILE"
    fi
    
    # ------------------------------------------------------------------------
    # LLVM Analysis (if enabled)
    # ------------------------------------------------------------------------
    
    if [ "$ENABLE_LLVM" = "true" ]; then
        echo "" | tee -a "$LOG_FILE"
        echo "--- LLVM IR Analysis ---" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        
        # Create temporary file for time output
        LLVM_TIME_FILE="$RESULTS_DIR/.time_llvm_${SAMPLE_NAME}_$$.tmp"
        
        # Run LLVM analysis with time measurement
        # Redirect stdout to log, stderr (time output) to temp file
        if /usr/bin/time -v "$LLVM_SCRIPT" "$SAMPLE" 2> "$LLVM_TIME_FILE" >> "$LOG_FILE"; then
            echo "LLVM analysis: SUCCESS" | tee -a "$LOG_FILE"
            LLVM_STATUS="success"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            echo "LLVM analysis: FAILED" | tee -a "$LOG_FILE"
            LLVM_STATUS="failed"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        fi
        
        # Append time output to log file
        cat "$LLVM_TIME_FILE" >> "$LOG_FILE"
        
        # Parse metrics from time output
        LLVM_METRICS=$(parse_time_output "$LLVM_TIME_FILE")
        
        # Write to CSV
        echo "$SAMPLE_NAME,llvm,$LLVM_METRICS,$LLVM_STATUS" >> "$CSV_FILE"
        
        # Clean up temp file
        rm -f "$LLVM_TIME_FILE"
    fi
    
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
