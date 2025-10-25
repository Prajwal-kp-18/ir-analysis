#!/bin/bash
#
# verify_cfg_implementation.sh
# Quick verification script to test CFG metrics implementation
#

set -e

echo "=========================================="
echo "CFG Metrics Implementation Verification"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

# Function to check if a file exists
check_file() {
    local file=$1
    local description=$2
    
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $description exists: $file"
        ((PASS++))
        return 0
    else
        echo -e "${RED}✗${NC} $description missing: $file"
        ((FAIL++))
        return 1
    fi
}

# Function to check if string exists in file
check_string() {
    local file=$1
    local pattern=$2
    local description=$3
    
    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $description found in $file"
        ((PASS++))
        return 0
    else
        echo -e "${RED}✗${NC} $description NOT found in $file"
        ((FAIL++))
        return 1
    fi
}

echo "1. Checking file existence..."
echo "---"
check_file "scripts/analyze_angr.py" "angr analysis script"
check_file "scripts/analyze_ghidra.sh" "Ghidra analysis script"
check_file "scripts/get_cfg_stats.py" "Ghidra CFG stats post-script"
check_file "scripts/run_all.sh" "Main orchestration script"
echo ""

echo "2. Checking analyze_angr.py modifications..."
echo "---"
check_string "scripts/analyze_angr.py" "ANGR_STATS:Functions" "angr function stats output"
check_string "scripts/analyze_angr.py" "ANGR_STATS:Nodes" "angr nodes stats output"
check_string "scripts/analyze_angr.py" "ANGR_STATS:Edges" "angr edges stats output"
check_string "scripts/analyze_angr.py" "cfg.kb.functions" "angr CFG function extraction"
echo ""

echo "3. Checking get_cfg_stats.py content..."
echo "---"
check_string "scripts/get_cfg_stats.py" "GHIDRA_STATS:Functions" "Ghidra function stats output"
check_string "scripts/get_cfg_stats.py" "GHIDRA_STATS:BasicBlocks" "Ghidra basic blocks stats output"
check_string "scripts/get_cfg_stats.py" "BasicBlockModel" "Ghidra BasicBlockModel usage"
check_string "scripts/get_cfg_stats.py" "FunctionManager" "Ghidra FunctionManager usage"
echo ""

echo "4. Checking analyze_ghidra.sh modifications..."
echo "---"
check_string "scripts/analyze_ghidra.sh" "POST_SCRIPT_PATH" "Post-script path variable"
check_string "scripts/analyze_ghidra.sh" "get_cfg_stats.py" "Post-script reference"
check_string "scripts/analyze_ghidra.sh" "-postScript" "Post-script argument"
echo ""

echo "5. Checking run_all.sh modifications..."
echo "---"
check_string "scripts/run_all.sh" "GHIDRA_STDOUT_FILE" "Ghidra stdout capture"
check_string "scripts/run_all.sh" "ANGR_STDOUT_FILE" "angr stdout capture"
check_string "scripts/run_all.sh" 'grep "GHIDRA_STATS:"' "Ghidra stats extraction"
check_string "scripts/run_all.sh" 'grep "ANGR_STATS:"' "angr stats extraction"
check_string "scripts/run_all.sh" "Ghidra CFG Stats:" "Ghidra CFG stats logging"
check_string "scripts/run_all.sh" "angr CFG Stats:" "angr CFG stats logging"
echo ""

echo "6. Checking script permissions..."
echo "---"
if [ -x "scripts/analyze_angr.py" ]; then
    echo -e "${GREEN}✓${NC} analyze_angr.py is executable"
    ((PASS++))
else
    echo -e "${YELLOW}⚠${NC} analyze_angr.py is not executable (may need: chmod +x scripts/analyze_angr.py)"
fi

if [ -x "scripts/analyze_ghidra.sh" ]; then
    echo -e "${GREEN}✓${NC} analyze_ghidra.sh is executable"
    ((PASS++))
else
    echo -e "${RED}✗${NC} analyze_ghidra.sh is not executable"
    ((FAIL++))
fi

if [ -x "scripts/run_all.sh" ]; then
    echo -e "${GREEN}✓${NC} run_all.sh is executable"
    ((PASS++))
else
    echo -e "${RED}✗${NC} run_all.sh is not executable"
    ((FAIL++))
fi
echo ""

echo "=========================================="
echo "Verification Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Test angr: python3 scripts/analyze_angr.py /bin/ls | grep ANGR_STATS:"
    echo "2. Test Ghidra: ./scripts/analyze_ghidra.sh /bin/ls | grep GHIDRA_STATS:"
    echo "3. Run full benchmark: ./scripts/run_all.sh"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some checks failed. Please review the errors above.${NC}"
    echo ""
    exit 1
fi
