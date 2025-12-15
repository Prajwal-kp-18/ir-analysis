#!/bin/bash
#
# install_llvm_lifter.sh
# Attempts to set up an LLVM lifter (RetDec or mctoll).
#
# Note: McSema and Remill have complex dependencies (IDA Pro, specific LLVM versions).
# This script focuses on RetDec (Avast) or llvm-mctoll as they are more standalone.
#

INSTALL_DIR="${HOME}/tools/llvm-lifters"
mkdir -p "$INSTALL_DIR"

echo "=========================================="
echo "LLVM Lifter Setup"
echo "=========================================="
echo "Target Directory: $INSTALL_DIR"
echo ""

# Check for existing tools
if command -v retdec-decompiler &> /dev/null; then
    echo "SUCCESS: RetDec is already installed and in PATH."
    exit 0
fi

if command -v llvm-mctoll &> /dev/null; then
    echo "SUCCESS: llvm-mctoll is already installed and in PATH."
    exit 0
fi

echo "Checking for pre-built binaries..."

# 1. Try RetDec (Avast)
# RetDec releases are often distributed as archives.
# URL: https://github.com/avast/retdec/releases
# We will check if we can download a known version.

RETDEC_VER="v4.0"
RETDEC_URL="https://github.com/avast/retdec/releases/download/${RETDEC_VER}/retdec-${RETDEC_VER}-ubuntu-64b.tar.xz"

echo "Attempting to download RetDec $RETDEC_VER..."

if wget -q --spider "$RETDEC_URL"; then
    echo "Downloading RetDec..."
    wget -O "$INSTALL_DIR/retdec.tar.xz" "$RETDEC_URL"
    
    echo "Extracting..."
    tar -xf "$INSTALL_DIR/retdec.tar.xz" -C "$INSTALL_DIR"
    
    # Find the bin directory
    RETDEC_BIN=$(find "$INSTALL_DIR" -type d -name "bin" | grep "retdec" | head -n 1)
    
    if [ -d "$RETDEC_BIN" ]; then
        echo ""
        echo "SUCCESS: RetDec installed to $RETDEC_BIN"
        echo "Please add this to your PATH:"
        echo "export PATH=\$PATH:$RETDEC_BIN"
        exit 0
    fi
else
    echo "WARNING: Could not download RetDec. Internet access might be restricted or URL changed."
fi

echo ""
echo "------------------------------------------"
echo "Manual Installation Required"
echo "------------------------------------------"
echo "Could not automatically install a lifter. Please install one of the following:"
echo ""
echo "1. RetDec (https://github.com/avast/retdec)"
echo "   - Download release, extract, add 'bin' to PATH."
echo ""
echo "2. llvm-mctoll (https://github.com/microsoft/llvm-mctoll)"
echo "   - Clone and build from source (requires LLVM)."
echo ""
echo "3. McSema (https://github.com/lifting-bits/mcsema)"
echo "   - Follow official instructions (complex setup)."
echo ""
echo "After installation, ensure the tool (retdec-decompiler, llvm-mctoll, or mcsema-lift) is in your PATH."
echo "Then re-run run_all.sh with ENABLE_LLVM=true."

exit 1
