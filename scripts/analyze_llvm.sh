#!/bin/bash
#
# analyze_llvm.sh
# Analyzes a binary using LLVM toolchain and attempts to generate LLVM IR.
#
# Usage: ./analyze_llvm.sh <path_to_binary>
#
# Prerequisites:
#   - LLVM toolchain installed (llvm-dis, llvm-objdump, opt)
#   - For best results with compiled binaries, consider using:
#     - mcsema (https://github.com/lifting-bits/mcsema) for binary lifting
#     - remill (https://github.com/lifting-bits/remill) for instruction semantics
#
# Note: This script provides basic LLVM IR analysis. For production use,
#       consider integrating specialized binary lifting tools.
#

# ============================================================================
# CONFIGURATION BLOCK - Edit these paths to match your setup
# ============================================================================

# LLVM tools (usually available in PATH if installed via package manager)
LLVM_DIS="${LLVM_DIS:-llvm-dis}"
LLVM_OBJDUMP="${LLVM_OBJDUMP:-llvm-objdump}"
LLVM_OPT="${LLVM_OPT:-opt}"

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

# Check for at least one LLVM tool
LLVM_AVAILABLE=false

if command -v "$LLVM_OBJDUMP" &> /dev/null; then
    LLVM_AVAILABLE=true
fi

if command -v "$LLVM_DIS" &> /dev/null; then
    LLVM_AVAILABLE=true
fi

if [ "$LLVM_AVAILABLE" = false ]; then
    echo "ERROR: No LLVM tools found" >&2
    echo "Please install LLVM toolchain:" >&2
    echo "  Ubuntu/Debian: sudo apt install llvm" >&2
    echo "  Or download from: https://releases.llvm.org/" >&2
    exit 1
fi

# ============================================================================
# SETUP
# ============================================================================

BINARY_NAME=$(basename "$BINARY_PATH")

echo "=========================================="
echo "LLVM IR Analysis"
echo "=========================================="
echo "Binary:  $BINARY_PATH"
echo "=========================================="

# ============================================================================
# DETECT FILE TYPE
# ============================================================================

# Check if this is LLVM bitcode
FILE_TYPE=$(file "$BINARY_PATH")

if [[ "$FILE_TYPE" == *"LLVM"* ]] || [[ "$FILE_TYPE" == *"bitcode"* ]]; then
    echo ""
    echo "Detected LLVM bitcode file"
    echo "Disassembling to LLVM IR..."
    echo ""
    
    # Disassemble LLVM bitcode to IR
    if command -v "$LLVM_DIS" &> /dev/null; then
        "$LLVM_DIS" "$BINARY_PATH" -o - 2>&1
        EXIT_STATUS=$?
    else
        echo "ERROR: llvm-dis not found, cannot disassemble bitcode" >&2
        exit 1
    fi
else
    # Check for true lifters
    LIFTER_CMD=""
    LIFTER_TYPE=""
    
    if command -v retdec-decompiler &> /dev/null; then
        LIFTER_CMD="retdec-decompiler"
        LIFTER_TYPE="retdec"
    elif command -v llvm-mctoll &> /dev/null; then
        LIFTER_CMD="llvm-mctoll"
        LIFTER_TYPE="mctoll"
    fi
    
    if [ -n "$LIFTER_CMD" ]; then
        echo "Found LLVM lifter: $LIFTER_CMD"
        echo "Lifting binary to LLVM IR..."
        
        LLVM_IR_FILE="${BINARY_PATH}.ll"
        
        if [ "$LIFTER_TYPE" = "retdec" ]; then
            # RetDec generates: .bc (LLVM bitcode), .ll (LLVM IR), .c (C code), .dsm (disassembly)
            echo "Running RetDec decompiler..."
            "$LIFTER_CMD" "$BINARY_PATH" 2>&1 | grep -v "^\s*$" | head -20
            
            LLVM_BC_FILE="${BINARY_PATH}.bc"
            LLVM_IR_FILE="${BINARY_PATH}.ll"
            
            # RetDec already generates .ll file directly
            if [ -f "$LLVM_IR_FILE" ] && [ -f "$LLVM_BC_FILE" ]; then
                echo ""
                echo "Found LLVM IR file: $LLVM_IR_FILE"
                echo "Analyzing LLVM IR structure..."
                
                # Count functions (lines starting with "define")
                NUM_FUNCTIONS=$(grep -c "^define " "$LLVM_IR_FILE" || echo "0")
                
                # Count basic blocks (labels in LLVM IR end with :)
                NUM_BLOCKS=$(grep -cE "^[a-zA-Z0-9_]+:\s*$" "$LLVM_IR_FILE" || echo "0")
                
                # Count LLVM instructions (lines with assignments or known instructions)
                NUM_INSTR=$(grep -cE "^\s*(%.* = |  (store|load|call|br|ret|add|sub|mul|icmp|getelementptr|alloca|bitcast|phi|select|switch|and|or|xor|shl|lshr|ashr|fadd|fsub|fmul|fdiv|fcmp|extractvalue|insertvalue|extractelement|insertelement))" "$LLVM_IR_FILE" || echo "0")
                
                echo ""
                echo "--- LLVM IR Stats ---"
                echo "LLVM_STATS:Functions=$NUM_FUNCTIONS"
                echo "LLVM_STATS:BasicBlocks=$NUM_BLOCKS"
                echo "LLVM_STATS:TotalLlvmInstructions=$NUM_INSTR"
                echo "---------------------"
                
                # Cleanup temporary files
                rm -f "$LLVM_IR_FILE" "$LLVM_BC_FILE" "${BINARY_PATH}.c" "${BINARY_PATH}.dsm" "${BINARY_PATH}.config.json"
                EXIT_STATUS=0
            else
                echo "ERROR: RetDec did not generate IR files"
                echo "Expected .bc at: $LLVM_BC_FILE"
                echo "Expected .ll at: $LLVM_IR_FILE"
                EXIT_STATUS=1
            fi
            
        elif [ "$LIFTER_TYPE" = "mctoll" ]; then
            # llvm-mctoll usage: llvm-mctoll -d input_file > output.ll
            "$LIFTER_CMD" -d "$BINARY_PATH" > "$LLVM_IR_FILE" 2>/dev/null
            
            if [ -s "$LLVM_IR_FILE" ]; then
                cat "$LLVM_IR_FILE"
                 # Count stats
                NUM_INSTR=$(grep -cE "^[[:space:]]*[a-z]+" "$LLVM_IR_FILE")
                echo ""
                echo "--- LLVM IR Stats ---"
                echo "LLVM_STATS:Functions=0"
                echo "LLVM_STATS:BasicBlocks=0"
                echo "LLVM_STATS:TotalLlvmInstructions=$NUM_INSTR"
                echo "---------------------"
                
                rm -f "$LLVM_IR_FILE"
                EXIT_STATUS=0
            else
                 echo "WARNING: llvm-mctoll failed to generate output."
                 EXIT_STATUS=1
            fi
        fi
        
    else
        echo "No dedicated LLVM lifter found (RetDec/mctoll)."
        echo "Falling back to llvm-objdump for disassembly analysis (Proxy for IR)."
        echo ""
    
        if command -v "$LLVM_OBJDUMP" &> /dev/null; then
            echo "--- Binary Information ---"
            "$LLVM_OBJDUMP" -h "$BINARY_PATH" 2>&1
            
            echo ""
            echo "--- Disassembly (first 100 instructions) ---"
            "$LLVM_OBJDUMP" -d "$BINARY_PATH" 2>&1 | head -n 150
            
            # Count assembly instructions as a proxy
            NUM_INSTR=$("$LLVM_OBJDUMP" -d "$BINARY_PATH" | grep -cE "^[[:space:]]*[0-9a-f]+:")
            
            echo ""
            echo "--- LLVM IR Stats (Proxy: Assembly) ---"
            echo "LLVM_STATS:Functions=0"
            echo "LLVM_STATS:BasicBlocks=0"
            echo "LLVM_STATS:TotalLlvmInstructions=$NUM_INSTR"
            echo "---------------------------------------"
            
            EXIT_STATUS=0
            
            echo ""
            echo "NOTE: For true binary-to-LLVM IR lifting, please install RetDec or llvm-mctoll."
            echo "      Run scripts/install_llvm_lifter.sh to attempt installation."
        else
            echo "ERROR: llvm-objdump not found" >&2
            exit 1
        fi
    fi
fi

# ============================================================================
# ERROR HANDLING
# ============================================================================

if [ $EXIT_STATUS -ne 0 ]; then
    echo "" >&2
    echo "ERROR: LLVM analysis failed with exit code $EXIT_STATUS" >&2
    exit 1
fi

echo ""
echo "=========================================="
echo "LLVM analysis completed successfully"
echo "=========================================="

exit 0
