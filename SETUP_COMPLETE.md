# IR Lifting Benchmark - Setup Complete! ✓

## Installation Summary

All required components have been successfully installed and configured:

### ✓ Installed Components

1. **Python Virtual Environment** (`.venv/`)
   - Python 3.12
   - angr 9.2.188 (binary analysis framework)
   - All dependencies installed

2. **Ghidra** 
   - Location: `/opt/ghidra`
   - Status: Found and ready

3. **RetDec** (LLVM Lifter)
   - Location: `/home/prajwal/tools/llvm-lifters/retdec/bin`
   - Status: Installed (requires PATH configuration)

4. **LLVM Toolchain**
   - Status: Installed

5. **Sample Files**
   - Benign samples: 6 test binaries in `samples/benign/`
   - Malware samples: Ready for your samples in `samples/malware/`

### ⚠️ Optional Components (Not Installed)

- **BAP**: Not installed (optional, can be enabled with `ENABLE_BAP=true`)

---

## Quick Start Guide

### 1. Activate the Environment

Before running any analysis, activate the Python virtual environment and load environment variables:

```bash
cd /home/prajwal/Documents/ir-analysis
source .venv/bin/activate
source .env
```

### 2. Test the Setup

Run a quick test on the benign samples:

```bash
# Override the samples directory to use benign samples for testing
SAMPLES_DIR=samples/benign ./scripts/run_all.sh
```

This will analyze the 6 benign test binaries using:
- Ghidra (P-code analysis)
- angr (VEX IR analysis)
- LLVM (RetDec lifting)

### 3. Analyze Your Own Samples

Place your malware samples in `samples/malware/` and run:

```bash
./scripts/run_all.sh
```

### 4. Generate Report

After analysis completes, generate a summary report:

```bash
python3 scripts/report_generator.py
```

View the report at `results/benchmark_report.md`

---

## Configuration

All configuration is stored in `.env` file:

```bash
# Ghidra installation path
export GHIDRA_INSTALL_DIR=/opt/ghidra

# RetDec binary path (added to PATH)
export PATH=$PATH:/home/prajwal/tools/llvm-lifters/retdec/bin

# Optional tool flags
export ENABLE_BAP=false    # Set to 'true' to enable BAP (if installed)
export ENABLE_LLVM=true    # LLVM analysis enabled

# Analysis timeout (seconds)
export TIMEOUT_SECONDS=60
```

To modify settings, edit `.env` and re-source it:
```bash
source .env
```

---

## Directory Structure

```
ir-analysis/
├── .venv/                      # Python virtual environment
├── .env                        # Environment configuration
├── samples/
│   ├── benign/                # Test binaries (6 samples)
│   └── malware/               # Your malware samples (empty, ready for use)
├── scripts/
│   ├── run_all.sh            # Main orchestration script
│   ├── analyze_ghidra.sh     # Ghidra P-code analysis
│   ├── analyze_angr.py       # angr VEX IR analysis
│   ├── analyze_llvm.sh       # LLVM lifting with RetDec
│   ├── analyze_bap.sh        # BAP BIL analysis (optional)
│   └── report_generator.py   # Generate benchmark report
└── results/                   # Analysis outputs (created on first run)
```

---

## Troubleshooting

### RetDec not in PATH
If you see "retdec-decompiler not found":
```bash
source .env
```

### Ghidra not found
Verify Ghidra location:
```bash
echo $GHIDRA_INSTALL_DIR
ls $GHIDRA_INSTALL_DIR/ghidraRun
```

### angr import errors
Ensure virtual environment is activated:
```bash
source .venv/bin/activate
python3 -c "import angr; print(angr.__version__)"
```

### Permission denied on scripts
Make scripts executable:
```bash
chmod +x scripts/*.sh
```

---

## Next Steps

1. **Test with benign samples**: `SAMPLES_DIR=samples/benign ./scripts/run_all.sh`
2. **Add your malware samples** to `samples/malware/`
3. **Run full benchmark**: `./scripts/run_all.sh`
4. **Generate report**: `python3 scripts/report_generator.py`
5. **Customize timeouts** and paths in `.env` as needed

---

## Advanced: Installing BAP (Optional)

If you want to enable BAP (Binary Analysis Platform):

```bash
# Initialize opam (if not already done)
opam init -y --disable-sandboxing
eval $(opam env)

# Install BAP
opam install bap -y

# Enable BAP in configuration
export ENABLE_BAP=true

# Run benchmark with BAP
ENABLE_BAP=true ./scripts/run_all.sh
```

---

**Setup completed on:** December 16, 2025  
**Ready to analyze binaries!** 🚀
