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
# In single-file mode, we'll override this after argument parsing
SAMPLES_DIR="${SAMPLES_DIR:-$(dirname "$(dirname "$(readlink -f "$0")")")/samples/malware}"

# Directory where results and logs will be written
# Default: results/ relative to project root  
RESULTS_DIR="${RESULTS_DIR:-$(dirname "$(dirname "$(readlink -f "$0")")")/results/malware}"

# Output log file name (will be created in RESULTS_DIR)
OUTPUT_LOG="${OUTPUT_LOG:-analysis_results.log}"

# CSV summary file name (will be created in RESULTS_DIR)
CSV_SUMMARY="${CSV_SUMMARY:-summary.csv}"

# Path to Ghidra installation (required by analyze_ghidra.sh)
# This can also be set as an environment variable before running this script
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"

# Enable BAP analysis (set to "true" to enable, "false" or empty to disable)
# BAP must be installed via opam for this to work
ENABLE_BAP="${ENABLE_BAP:-false}"

# Enable LLVM analysis (set to "true" to enable, "false" or empty to disable)
# LLVM toolchain must be installed for this to work
ENABLE_LLVM="${ENABLE_LLVM:-true}"

# Timeout for each individual tool analysis (in seconds)
# Set to 0 to disable timeout
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-3600}"
# ============================================================================
# SCRIPT SETUP
# ============================================================================

# Check for single-file mode first
SINGLE_FILE_MODE=false
SINGLE_FILE_PATH=""
if [ "$1" = "--single" ] && [ -n "$2" ]; then
    SINGLE_FILE_MODE=true
    SINGLE_FILE_PATH="$2"
    # Override SAMPLES_DIR to parent directory of the file
    SAMPLES_DIR="$(dirname "$SINGLE_FILE_PATH")"
fi

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Paths to the analysis scripts
GHIDRA_SCRIPT="$SCRIPT_DIR/analyze_ghidra.sh"
ANGR_SCRIPT="$SCRIPT_DIR/analyze_angr.py"
BAP_SCRIPT="$SCRIPT_DIR/analyze_bap.sh"
LLVM_SCRIPT="$SCRIPT_DIR/analyze_llvm.sh"

# Full path to output log and CSV summary
LOG_FILE="$RESULTS_DIR/$OUTPUT_LOG"
CSV_FILE="$RESULTS_DIR/$CSV_SUMMARY"

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
echo "Timeout: ${TIMEOUT_SECONDS}s"
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
    # Check for bap_docker.sh wrapper or native bap
    if [ -x "$SCRIPT_DIR/bap_docker.sh" ]; then
        echo "Using BAP via Docker wrapper"
    elif ! command -v bap &> /dev/null; then
        echo "WARNING: BAP is enabled but 'bap' command not found" >&2
        echo "Please install BAP via opam or ensure Docker is available:" >&2
        echo "  1. sudo apt install opam" >&2
        echo "  2. opam init" >&2
        echo "  3. opam install bap" >&2
        echo "Or ensure bap_docker.sh wrapper exists and Docker image is pulled" >&2
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
# New Schema: Sample_ID,Architecture,Tool,Success_Status,Time_s,Mem_MB,Func_Count,Block_Count,IR_Stmt_Count
if [ "$1" = "--single" ]; then
    # Single file mode: only create header if file doesn't exist
    if [ ! -f "$CSV_FILE" ]; then
        echo "Sample_ID,Architecture,Tool,Success_Status,Time_s,Mem_MB,Func_Count,Block_Count,IR_Stmt_Count" > "$CSV_FILE"
    fi
else
    # Normal mode: overwrite with new header
    echo "Sample_ID,Architecture,Tool,Success_Status,Time_s,Mem_MB,Func_Count,Block_Count,IR_Stmt_Count" > "$CSV_FILE"
fi

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
# HELPER FUNCTIONS
# ============================================================================

parse_time_output() {
    local time_file="$1"
    local elapsed="0"
    local max_rss="0"
    
    if [ -f "$time_file" ]; then
        # Extract elapsed time (format: h:mm:ss or m:ss.ms)
        local raw_elapsed=$(grep "Elapsed (wall clock) time" "$time_file" | awk '{print $NF}' | sed 's/[()]//g')
        # echo "DEBUG: raw_elapsed='$raw_elapsed'" >> "$LOG_FILE"
        
        # Convert elapsed time to seconds
        if [[ "$raw_elapsed" =~ ^([0-9]+):([0-9]+):([0-9.]+)$ ]]; then
            # Format: h:mm:ss.ms
            local hours="${BASH_REMATCH[1]}"
            local minutes="${BASH_REMATCH[2]}"
            local seconds="${BASH_REMATCH[3]}"
            elapsed=$(echo "$hours * 3600 + $minutes * 60 + $seconds" | bc)
        elif [[ "$raw_elapsed" =~ ^([0-9]+):([0-9.]+)$ ]]; then
            # Format: m:ss.ms
            local minutes="${BASH_REMATCH[1]}"
            local seconds="${BASH_REMATCH[2]}"
            elapsed=$(echo "$minutes * 60 + $seconds" | bc)
        fi
        
        # Extract maximum resident set size (in KB) -> Convert to MB
        local raw_rss=$(grep "Maximum resident set size" "$time_file" | awk '{print $NF}')
        if [ ! -z "$raw_rss" ]; then
            max_rss=$(echo "scale=2; $raw_rss / 1024" | bc)
        fi
    fi
    
    echo "$elapsed,$max_rss"
}

parse_stats() {
    local log_file="$1"
    local prefix="$2"
    
    local funcs="0"
    local blocks="0"
    local stmts="0"
    
    if [ -f "$log_file" ]; then
        funcs=$(grep "${prefix}:Functions=" "$log_file" | cut -d'=' -f2 | head -n1)
        blocks=$(grep "${prefix}:BasicBlocks=" "$log_file" | cut -d'=' -f2 | head -n1)
        # Handle different naming for IR statements
        if [ "$prefix" = "GHIDRA_STATS" ]; then
            stmts=$(grep "${prefix}:TotalPcodeOps=" "$log_file" | cut -d'=' -f2 | head -n1)
        elif [ "$prefix" = "ANGR_STATS" ]; then
            stmts=$(grep "${prefix}:TotalVexStatements=" "$log_file" | cut -d'=' -f2 | head -n1)
        elif [ "$prefix" = "BAP_STATS" ]; then
            stmts=$(grep "${prefix}:TotalBilStatements=" "$log_file" | cut -d'=' -f2 | head -n1)
        elif [ "$prefix" = "LLVM_STATS" ]; then
            stmts=$(grep "${prefix}:TotalLlvmInstructions=" "$log_file" | cut -d'=' -f2 | head -n1)
        fi
        
        # Fallback to Nodes if BasicBlocks not found (for angr compatibility if needed)
        if [ -z "$blocks" ] && [ "$prefix" = "ANGR_STATS" ]; then
             blocks=$(grep "${prefix}:Nodes=" "$log_file" | cut -d'=' -f2 | head -n1)
        fi
    fi
    
    # Default to 0 if empty
    funcs="${funcs:-0}"
    blocks="${blocks:-0}"
    stmts="${stmts:-0}"
    
    echo "$funcs,$blocks,$stmts"
}

get_architecture() {
    # Placeholder: In a real scenario, use 'file' command or read from metadata.
    # For now, we'll try to guess from path or file command, or default to "Unknown"
    local sample_path="$1"
    # Try to extract from parent directory name if it matches known archs
    local parent_dir=$(basename "$(dirname "$sample_path")")
    if [[ "$parent_dir" =~ ^(x86|ARM|MIPS|PowerPC|Coldfire|SuperH4) ]]; then
        echo "$parent_dir"
    else
        # Fallback to file command
        file -b "$sample_path" | cut -d',' -f2 | xargs
    fi
}

# Loop through all files in the samples directory
# Support recursive search if samples are organized by architecture
if [ "$SINGLE_FILE_MODE" = "true" ]; then
    # Single file mode: process only the specified file
    SAMPLE_LIST=("$SINGLE_FILE_PATH")
else
    # Normal mode: find all files in SAMPLES_DIR
    mapfile -t SAMPLE_LIST < <(find "$SAMPLES_DIR" -type f)
fi

for SAMPLE in "${SAMPLE_LIST[@]}"; do
    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))
    SAMPLE_NAME=$(basename "$SAMPLE")
    ARCH=$(get_architecture "$SAMPLE")
    
    echo "========================================" | tee -a "$LOG_FILE"
    echo "Processing sample: $SAMPLE_NAME ($ARCH)" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
    
    # ------------------------------------------------------------------------
    # Ghidra Analysis
    # ------------------------------------------------------------------------
    
    echo "" | tee -a "$LOG_FILE"
    echo "--- Ghidra P-code Analysis ---" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    GHIDRA_TIME_FILE="$RESULTS_DIR/.time_ghidra_${SAMPLE_NAME}_$$.tmp"
    GHIDRA_STDOUT_FILE="$RESULTS_DIR/.stdout_ghidra_${SAMPLE_NAME}_$$.tmp"
    
    # Run with timeout
    /usr/bin/time -v timeout "${TIMEOUT_SECONDS}s" "$GHIDRA_SCRIPT" "$SAMPLE" > "$GHIDRA_STDOUT_FILE" 2> "$GHIDRA_TIME_FILE"
    EXIT_CODE=$?
    
    GHIDRA_STATUS="Success"
    if [ $EXIT_CODE -eq 124 ]; then
        echo "Ghidra analysis: TIMEOUT (${TIMEOUT_SECONDS}s)" | tee -a "$LOG_FILE"
        GHIDRA_STATUS="Failure - Timeout"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    elif [ $EXIT_CODE -ne 0 ]; then
        echo "Ghidra analysis: FAILED (Exit Code: $EXIT_CODE)" | tee -a "$LOG_FILE"
        echo "--- Ghidra Stderr ---" >> "$LOG_FILE"
        cat "$GHIDRA_TIME_FILE" >> "$LOG_FILE"
        echo "---------------------" >> "$LOG_FILE"
        GHIDRA_STATUS="Failure - Crash"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    else
        echo "Ghidra analysis: SUCCESS" | tee -a "$LOG_FILE"
    fi
    
    cat "$GHIDRA_STDOUT_FILE" >> "$LOG_FILE"
    
    # Parse metrics
    GHIDRA_PERF=$(parse_time_output "$GHIDRA_TIME_FILE")
    GHIDRA_STATS=$(parse_stats "$GHIDRA_STDOUT_FILE" "GHIDRA_STATS")
    
    # If failed, zero out stats
    if [[ "$GHIDRA_STATUS" != "Success" ]]; then
        GHIDRA_STATS="0,0,0"
    fi
    
    echo "$SAMPLE_NAME,$ARCH,ghidra,$GHIDRA_STATUS,$GHIDRA_PERF,$GHIDRA_STATS" >> "$CSV_FILE"
    
    rm -f "$GHIDRA_TIME_FILE" "$GHIDRA_STDOUT_FILE"
    
    # ------------------------------------------------------------------------
    # angr Analysis
    # ------------------------------------------------------------------------
    
    echo "" | tee -a "$LOG_FILE"
    echo "--- angr VEX IR Analysis ---" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    ANGR_TIME_FILE="$RESULTS_DIR/.time_angr_${SAMPLE_NAME}_$$.tmp"
    ANGR_STDOUT_FILE="$RESULTS_DIR/.stdout_angr_${SAMPLE_NAME}_$$.tmp"
    
    /usr/bin/time -v timeout "${TIMEOUT_SECONDS}s" python3 "$ANGR_SCRIPT" "$SAMPLE" > "$ANGR_STDOUT_FILE" 2> "$ANGR_TIME_FILE"
    EXIT_CODE=$?
    
    ANGR_STATUS="Success"
    if [ $EXIT_CODE -eq 124 ]; then
        echo "angr analysis: TIMEOUT (${TIMEOUT_SECONDS}s)" | tee -a "$LOG_FILE"
        ANGR_STATUS="Failure - Timeout"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    elif [ $EXIT_CODE -ne 0 ]; then
        echo "angr analysis: FAILED (Exit Code: $EXIT_CODE)" | tee -a "$LOG_FILE"
        ANGR_STATUS="Failure - Crash"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    else
        echo "angr analysis: SUCCESS" | tee -a "$LOG_FILE"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
    
    cat "$ANGR_STDOUT_FILE" >> "$LOG_FILE"
    
    ANGR_PERF=$(parse_time_output "$ANGR_TIME_FILE")
    ANGR_STATS=$(parse_stats "$ANGR_STDOUT_FILE" "ANGR_STATS")
    
    if [[ "$ANGR_STATUS" != "Success" ]]; then
        ANGR_STATS="0,0,0"
    fi
    
    echo "$SAMPLE_NAME,$ARCH,angr,$ANGR_STATUS,$ANGR_PERF,$ANGR_STATS" >> "$CSV_FILE"
    
    rm -f "$ANGR_TIME_FILE" "$ANGR_STDOUT_FILE"
    
    # ------------------------------------------------------------------------
    # BAP Analysis (if enabled)
    # ------------------------------------------------------------------------
    
    if [ "$ENABLE_BAP" = "true" ]; then
        echo "" | tee -a "$LOG_FILE"
        echo "--- BAP BIL IR Analysis ---" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        
        BAP_TIME_FILE="$RESULTS_DIR/.time_bap_${SAMPLE_NAME}_$$.tmp"
        BAP_STDOUT_FILE="$RESULTS_DIR/.stdout_bap_${SAMPLE_NAME}_$$.tmp"
        
        # Set BAP internal timeout to 60 seconds (per-binary timeout in analyze_bap.sh)
        export BAP_TIMEOUT=60
        /usr/bin/time -v timeout "${TIMEOUT_SECONDS}s" "$BAP_SCRIPT" "$SAMPLE" > "$BAP_STDOUT_FILE" 2> "$BAP_TIME_FILE"
        EXIT_CODE=$?
        
        BAP_STATUS="Success"
        if [ $EXIT_CODE -eq 124 ]; then
            echo "BAP analysis: TIMEOUT (${TIMEOUT_SECONDS}s)" | tee -a "$LOG_FILE"
            BAP_STATUS="Failure - Timeout"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        elif [ $EXIT_CODE -ne 0 ]; then
            echo "BAP analysis: FAILED (Exit Code: $EXIT_CODE)" | tee -a "$LOG_FILE"
            BAP_STATUS="Failure - Crash"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        else
            echo "BAP analysis: SUCCESS" | tee -a "$LOG_FILE"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        fi
        
        # Append output to log (optional, maybe too verbose)
        # cat "$BAP_STDOUT_FILE" >> "$LOG_FILE"
        
        BAP_PERF=$(parse_time_output "$BAP_TIME_FILE")
        BAP_STATS=$(parse_stats "$BAP_STDOUT_FILE" "BAP_STATS")
        
        if [[ "$BAP_STATUS" != "Success" ]]; then
            BAP_STATS="0,0,0"
        fi
        
        echo "$SAMPLE_NAME,$ARCH,bap,$BAP_STATUS,$BAP_PERF,$BAP_STATS" >> "$CSV_FILE"
        
        rm -f "$BAP_TIME_FILE" "$BAP_STDOUT_FILE"
    fi
    
    # ------------------------------------------------------------------------
    # LLVM Analysis (if enabled)
    # ------------------------------------------------------------------------
    
    if [ "$ENABLE_LLVM" = "true" ]; then
        echo "" | tee -a "$LOG_FILE"
        echo "--- LLVM IR Analysis ---" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        
        LLVM_TIME_FILE="$RESULTS_DIR/.time_llvm_${SAMPLE_NAME}_$$.tmp"
        LLVM_STDOUT_FILE="$RESULTS_DIR/.stdout_llvm_${SAMPLE_NAME}_$$.tmp"
        
        /usr/bin/time -v timeout "${TIMEOUT_SECONDS}s" "$LLVM_SCRIPT" "$SAMPLE" > "$LLVM_STDOUT_FILE" 2> "$LLVM_TIME_FILE"
        EXIT_CODE=$?
        
        LLVM_STATUS="Success"
        if [ $EXIT_CODE -eq 124 ]; then
            echo "LLVM analysis: TIMEOUT (${TIMEOUT_SECONDS}s)" | tee -a "$LOG_FILE"
            LLVM_STATUS="Failure - Timeout"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        elif [ $EXIT_CODE -ne 0 ]; then
            echo "LLVM analysis: FAILED (Exit Code: $EXIT_CODE)" | tee -a "$LOG_FILE"
            LLVM_STATUS="Failure - Crash"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        else
            echo "LLVM analysis: SUCCESS" | tee -a "$LOG_FILE"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        fi
        
        # Append output to log
        # cat "$LLVM_STDOUT_FILE" >> "$LOG_FILE"
        
        LLVM_PERF=$(parse_time_output "$LLVM_TIME_FILE")
        LLVM_STATS=$(parse_stats "$LLVM_STDOUT_FILE" "LLVM_STATS")
        
        if [[ "$LLVM_STATUS" != "Success" ]]; then
            LLVM_STATS="0,0,0"
        fi
        
        echo "$SAMPLE_NAME,$ARCH,llvm,$LLVM_STATUS,$LLVM_PERF,$LLVM_STATS" >> "$CSV_FILE"
        
        rm -f "$LLVM_TIME_FILE" "$LLVM_STDOUT_FILE"
    fi
    
    echo "" | tee -a "$LOG_FILE"
    echo "Completed: $SAMPLE_NAME" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
done

# ============================================================================
# SEMANTIC VALIDATION
# ============================================================================

echo "--- PHASE 2: SEMANTIC VALIDATION ON FOCUSED BLOCKS ---" | tee -a "$LOG_FILE"
# Run the validation script on the pre-defined JSON test cases
if [ -f "scripts/validation/validate_semantics.py" ] && [ -f "samples/validated_blocks/test_cases.json" ]; then
    python3 scripts/validation/validate_semantics.py samples/validated_blocks/test_cases.json >> "$LOG_FILE" 2>&1
    echo "Semantic validation completed. See results/semantic_report.csv" | tee -a "$LOG_FILE"
else
    echo "Skipping semantic validation (scripts or test cases not found)" | tee -a "$LOG_FILE"
fi

# ============================================================================
# SUMMARY
# ============================================================================

echo "========================================" | tee -a "$LOG_FILE"
echo "Benchmark Complete" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "Results saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "CSV summary saved to: $CSV_FILE" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"

exit 0
