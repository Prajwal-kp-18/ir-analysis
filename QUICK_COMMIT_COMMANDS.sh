#!/bin/bash
#
# QUICK_COMMIT_COMMANDS.sh
# Quick reference for committing to GitHub
#
# DO NOT RUN THIS SCRIPT DIRECTLY!
# Copy and paste commands as needed.
#

# ============================================================================
# STEP 1: CREATE GITHUB REPOSITORY
# ============================================================================
# Go to https://github.com/new
# Repository name: ir-benchmark-poc
# Description: IR Lifting Benchmark PoC - Comparing Ghidra P-code vs angr VEX IR
# Public repository
# DO NOT initialize with README, .gitignore, or license
# Click "Create repository"
# Copy the repository URL

# ============================================================================
# STEP 2: CONFIGURE GIT (if needed)
# ============================================================================

# Set your name and email
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# ============================================================================
# STEP 3: CONNECT TO GITHUB
# ============================================================================

# Add remote (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/ir-benchmark-poc.git

# Verify remote
git remote -v

# ============================================================================
# STEP 4: REVIEW FILES
# ============================================================================

# Check what will be committed
git status

# Verify .gitignore is working
git status --ignored

# ============================================================================
# STEP 5: STAGE FILES
# ============================================================================

# Add all files (respecting .gitignore)
git add .

# Verify staged files
git status

# Review what's being committed
git diff --cached --stat

# ============================================================================
# STEP 6: COMMIT
# ============================================================================

# Create initial commit
git commit -m "Initial commit: IR Benchmark PoC with Ghidra and angr scripts

- Add parameterized analysis scripts (analyze_ghidra.sh, analyze_angr.py)
- Add batch orchestration script with output parsing (run_all.sh)
- Include 6 benign sample binaries for testing
- Add malware safety guide (MALWARE_SAMPLES_GO_HERE.txt)
- Configure .gitignore to exclude malware and temporary files
- Add comprehensive README documentation"

# ============================================================================
# STEP 7: PUSH TO GITHUB
# ============================================================================

# Push to GitHub (first time)
git push -u origin main

# If your branch is named 'master', use:
# git push -u origin master

# ============================================================================
# VERIFICATION
# ============================================================================

# After pushing, visit your repository:
# https://github.com/YOUR_USERNAME/ir-benchmark-poc

# Verify:
# ✅ README.md is displayed
# ✅ scripts/ directory with 3 files
# ✅ samples/benign/ with 6 binaries
# ✅ samples/MALWARE_SAMPLES_GO_HERE.txt
# ✅ .gitignore
# ❌ NO samples/malware/ directory
# ❌ NO results/ files
# ❌ NO *.tmp files

# ============================================================================
# OPTIONAL: ADD LICENSE
# ============================================================================

# Create MIT License
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2025 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# Add and commit license
git add LICENSE
git commit -m "Add MIT License"
git push

# ============================================================================
# FUTURE UPDATES
# ============================================================================

# Make changes, then:
git add .
git commit -m "Description of changes"
git push

# ============================================================================
# TROUBLESHOOTING
# ============================================================================

# If remote already exists:
git remote remove origin
git remote add origin https://github.com/YOUR_USERNAME/ir-benchmark-poc.git

# If branch name mismatch:
git branch -M main
git push -u origin main

# If push rejected (remote has changes):
git pull origin main --rebase
git push

# Check what's being ignored:
git status --ignored

# See all tracked files:
git ls-files

echo "============================================================================"
echo "IMPORTANT: Do NOT run this script directly!"
echo "Copy and paste commands as needed, replacing YOUR_USERNAME with your GitHub username."
echo "============================================================================"
