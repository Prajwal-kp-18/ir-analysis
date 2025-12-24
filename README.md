# IR Lifting Benchmark

A comprehensive benchmarking suite for evaluating the performance, reliability, and accuracy of Intermediate Representation (IR) lifting tools used in binary analysis and security research. This framework provides automated analysis pipelines, comparative metrics, and visualization tools for assessing different IR lifting approaches on both benign and malware samples.

## Overview

This project provides a unified framework to benchmark multiple binary analysis tools that lift machine code to various intermediate representations. It's designed for security researchers, reverse engineers, and academics who need to:

- **Compare IR lifting tools** across different metrics (accuracy, performance, coverage)
- **Analyze malware samples** using multiple static analysis frameworks
- **Evaluate CFG recovery** and semantic preservation
- **Generate comprehensive reports** with statistics and visualizations

## Supported Tools

| Tool       | IR Type | Analysis Type                                  | Status    |
| ---------- | ------- | ---------------------------------------------- | --------- |
| **Ghidra** | P-code  | Static Analysis (Headless)                     | Core      |
| **angr**   | VEX     | Static Analysis (CFG Recovery)                 | Core      |
| **BAP**    | BIL     | Static Analysis (Lifting)                      | Optional  |
| **LLVM**   | LLVM IR | Lifting (RetDec/mctoll) or Disassembly (Proxy) | Optional  |

## Features

- ✅ **Multi-tool Support**: Analyze binaries with Ghidra, angr, BAP, and LLVM
- ✅ **Automated Workflows**: One-command setup and execution
- ✅ **Performance Metrics**: CPU time, memory usage, success rates
- ✅ **CFG Analysis**: Control flow graph extraction and statistics
- ✅ **Semantic Validation**: Verify semantic preservation of lifted IR
- ✅ **Visualization Tools**: Generate graphs and charts for analysis results
- ✅ **Batch Processing**: Analyze multiple samples in parallel
- ✅ **Dataset Support**: Works with Juliet Test Suite and custom malware datasets

## Prerequisites

- **OS**: Ubuntu 20.04/22.04 LTS (Recommended) or compatible Linux distribution
- **Ghidra**: Version 10.x or 11.x (Auto-configured if installed at `/opt/ghidra`)
- **Python**: 3.8+ (3.12 recommended)
- **Disk Space**: ~5GB for tools and dependencies
- **RAM**: 8GB minimum (16GB recommended for large samples)

## Quick Start

### 1. Setup Environment

Run the automated setup script to install system dependencies, Python venv, and tools (angr, BAP):

```bash
./setup.sh
```

### 2. Configure Ghidra

Set the path to your Ghidra installation:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.0.1_PUBLIC
```

### 3. Populate Dataset

Place your malware samples in the `samples/malware/<arch>/` directories.
(Benign samples are provided in `samples/benign/` for testing).

### 4. Run Benchmark

Activate the virtual environment and run the benchmark:

```bash
source .venv/bin/activate
./scripts/run_all.sh
```

To enable optional tools (BAP and LLVM):

```bash
ENABLE_BAP=true ENABLE_LLVM=true ./scripts/run_all.sh
```

### 5. Generate Report

After the benchmark completes, generate a summary report:

```bash
python3 scripts/report_generator.py
```

This creates `results/benchmark_report.md`.

## Directory Structure

```
ir-analysis/
├── scripts/              # Analysis and orchestration scripts
│   ├── analyze_angr.py       # angr analysis pipeline
│   ├── analyze_ghidra.sh     # Ghidra headless analysis
│   ├── analyze_bap.sh        # BAP analysis pipeline
│   ├── analyze_llvm.sh       # LLVM lifting pipeline
│   ├── report_generator.py   # Generate benchmark reports
│   ├── run_all.sh            # Master orchestration script
│   └── validation/           # Semantic validation tools
├── samples/              # Dataset directory
│   ├── benign/              # Benign test binaries
│   ├── malware/             # Malware samples (user-provided)
│   └── validated_blocks/    # Ground truth for validation
├── results/              # Analysis outputs
│ **Missing Ghidra?** Verify the install path and that `ghidraRun` is executable.
- **Python import errors?** Reactivate `.venv` and reinstall angr: `pip install angr`.
- **BAP not found?** Ensure opam is initialized and BAP is installed: `opam install bap && eval $(opam env)`.
- **LLVM not found?** Install LLVM toolchain: `sudo apt install llvm` or download from <https://releases.llvm.org/>.
- **Parsing failures?** Confirm GNU time output is English and scripts redirect stdout/stderr to the expected temp files.
- **Permission errors?** Ensure all scripts have execute permissions: `chmod +x scripts/*.sh *.sh`
├── activate.sh           # Quick environment activation
└── README.md             # This file
```

- **Parallel Jobs**: Control concurrency with `PARALLEL_JOBS` environment variable.

## Output and Reports

### Generated Files

- **`results/benchmark_report.md`**: Comprehensive benchmark report with tool comparisons
- **`results/malware/summary.csv`**: Per-sample analysis results
- **`results/malware/analysis_statistics.txt`**: Aggregate statistics
- **`results/semantic_report.csv`**: Semantic validation results
- **`results/*/tool_name.log`**: Individual tool execution logs

### Visualization

Generate visualizations of the analysis results:

```bash
python3 visualize_stats.py        # Generate charts from analysis results
python3 visualize_dataset.py      # Visualize dataset composition
python3 visualize_arch.py         # Architecture-specific analysis
```

## Dataset Information

### Benign Samples

The project includes 6 benign test binaries in `samples/benign/`:
- Simple programs (hello world, calculator, fibonacci)
- Array operations
- String manipulation

### Malware Samples

Place your malware samples in `samples/malware/`. The framework supports:
- ELF binaries (Linux)
- PE binaries (Windows) - with appropriate tool support
- Various architectures (x86, x64, ARM, MIPS, etc.)

### Juliet Test Suite

The framework includes support for the NSA Juliet Test Suite for CWE detection and validation.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- New tool integrations
- Performance improvements
- Bug fixes
- Documentation enhancements
- Additional validation tests

## Citation

If you use this benchmark in your research, please cite:

```bibtex
@software{ir_lifting_benchmark,
  title={IR Lifting Benchmark: A Comprehensive Framework for Binary Analysis Tool Evaluation},
  author={Prajwal},
  year={2025},
  url={https://github.com/yourusername/ir-analysis}
}
```

## Acknowledgments

This project leverages several open-source tools:
- [Ghidra](https://ghidra-sre.org/) - NSA's Software Reverse Engineering Framework
- [angr](https://angr.io/) - Binary analysis platform
- [BAP](https://github.com/BinaryAnalysisPlatform/bap) - Binary Analysis Platform
- [RetDec](https://github.com/avast/retdec) - Retargetable machine-code decompiler

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions, issues, or collaboration opportunities, please open an issue on GitHub or contact the maintainer.
To enable true binary-to-LLVM IR lifting, you need **RetDec** or **llvm-mctoll**.
Run the helper script to attempt installation:

```bash
./scripts/install_llvm_lifter.sh
```

- Missing Ghidra? Verify the install path and that `ghidraRun` is executable.
- Python import errors? Reactivate itialized and BAP is installed: `opam install bap && eval $(opam env)`.venv and reinstall angr.
- BAP not found? Ensure opam is in
- LLVM not found? Install LLVM toolchain: `sudo apt install llvm` or download from <https://releases.llvm.org/>.
- Parsing failures? Confirm GNU time output is English and scripts still redirect stdout/stderr to the expected temp files.

### Customization

- **Timeout**: Set `TIMEOUT_SECONDS` (default: 60s).
- **Paths**: Override `SAMPLES_DIR`, `RESULTS_DIR` via environment variables.

## License

[MIT License](LICENSE)
