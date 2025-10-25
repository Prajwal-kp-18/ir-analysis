#!/bin/bash
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║           Pre-Commit Security Verification                       ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0
WARN=0

# Test 1: Check for malware directory
echo "1. Checking for malware directory..."
if [ -d "samples/malware" ]; then
    echo "   ⚠️  WARNING: samples/malware/ exists!"
    ((WARN++))
else
    echo "   ✅ No malware directory"
    ((PASS++))
fi

# Test 2: Check for sensitive patterns
echo ""
echo "2. Checking for sensitive patterns..."
SENSITIVE=$(grep -r "password\|api_key\|secret\|token" --include="*.sh" --include="*.py" . 2>/dev/null | grep -v ".git" | grep -v "GITHUB_SETUP" | grep -v "PRE_COMMIT" | grep -v "verify_before_commit")
if [ -n "$SENSITIVE" ]; then
    echo "   ⚠️  WARNING: Potential sensitive data found!"
    echo "$SENSITIVE"
    ((WARN++))
else
    echo "   ✅ No obvious sensitive patterns"
    ((PASS++))
fi

# Test 3: Check .gitignore
echo ""
echo "3. Checking .gitignore..."
if [ -f ".gitignore" ] && grep -q "samples/malware" .gitignore; then
    echo "   ✅ .gitignore exists and excludes malware"
    ((PASS++))
else
    echo "   ❌ .gitignore missing or incomplete!"
    ((FAIL++))
fi

# Test 4: Check file types in samples/benign
echo ""
echo "4. Checking file types in samples/benign..."
NON_ELF=$(file samples/benign/* 2>/dev/null | grep -v "ELF")
if [ -n "$NON_ELF" ]; then
    echo "   ⚠️  Non-ELF files found:"
    echo "$NON_ELF"
    ((WARN++))
else
    echo "   ✅ All files are ELF binaries"
    ((PASS++))
fi

# Test 5: Check repository size
echo ""
echo "5. Checking repository size..."
SIZE=$(du -sh . 2>/dev/null | cut -f1)
echo "   Repository size: $SIZE"
((PASS++))

# Test 6: Check for large files
echo ""
echo "6. Checking for large files (>10MB)..."
LARGE=$(find . -type f -size +10M -not -path "./.git/*" 2>/dev/null)
if [ -n "$LARGE" ]; then
    echo "   ⚠️  Large files found:"
    echo "$LARGE"
    ((WARN++))
else
    echo "   ✅ No files over 10MB"
    ((PASS++))
fi

# Test 7: Check scripts are executable
echo ""
echo "7. Checking script permissions..."
if [ -x "scripts/analyze_ghidra.sh" ] && [ -x "scripts/analyze_angr.py" ] && [ -x "scripts/run_all.sh" ]; then
    echo "   ✅ All scripts are executable"
    ((PASS++))
else
    echo "   ⚠️  Some scripts may not be executable"
    ((WARN++))
fi

# Test 8: Check for unwanted files
echo ""
echo "8. Checking for unwanted files..."
UNWANTED=$(find . -name "__pycache__" -o -name ".DS_Store" -o -name "*.swp" -o -name "*~" 2>/dev/null | grep -v ".git")
if [ -n "$UNWANTED" ]; then
    echo "   ⚠️  Unwanted files found:"
    echo "$UNWANTED"
    ((WARN++))
else
    echo "   ✅ No unwanted files"
    ((PASS++))
fi

# Test 9: Check git status
echo ""
echo "9. Checking git status..."
if git status &>/dev/null; then
    UNTRACKED=$(git status --porcelain 2>/dev/null | grep "^??" | wc -l)
    echo "   ✅ Git repository initialized"
    echo "   Untracked files: $UNTRACKED"
    ((PASS++))
else
    echo "   ❌ Git not initialized!"
    ((FAIL++))
fi

# Test 10: Check required files exist
echo ""
echo "10. Checking required files..."
REQUIRED_FILES=("README.md" ".gitignore" "scripts/analyze_ghidra.sh" "scripts/analyze_angr.py" "scripts/run_all.sh" "samples/MALWARE_SAMPLES_GO_HERE.txt")
MISSING=""
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        MISSING="$MISSING $file"
    fi
done
if [ -z "$MISSING" ]; then
    echo "   ✅ All required files present"
    ((PASS++))
else
    echo "   ❌ Missing files:$MISSING"
    ((FAIL++))
fi

# Summary
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "Verification Results:"
echo "  ✅ Passed: $PASS"
echo "  ⚠️  Warnings: $WARN"
echo "  ❌ Failed: $FAIL"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
    echo "✅ ALL CHECKS PASSED! Repository is ready for GitHub."
    echo ""
    echo "Next steps:"
    echo "  1. Review GITHUB_SETUP_GUIDE.md for detailed instructions"
    echo "  2. Create GitHub repository at https://github.com/new"
    echo "  3. Run: git remote add origin <YOUR_REPO_URL>"
    echo "  4. Run: git add ."
    echo "  5. Run: git commit -m 'Initial commit: IR Benchmark PoC'"
    echo "  6. Run: git push -u origin main"
    exit 0
elif [ $FAIL -eq 0 ]; then
    echo "⚠️  WARNINGS DETECTED. Review above and proceed with caution."
    echo ""
    echo "If warnings are acceptable, you can proceed with commit."
    exit 0
else
    echo "❌ FAILURES DETECTED. DO NOT COMMIT until issues are resolved!"
    exit 1
fi
