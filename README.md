# IR Lifting Benchmark PoC (Ghidra vs. angr vs. BAP)

## 1. Project overview

Benchmarks IR lifting performance of Ghidra (P-code), angr (VEX), BAP (BIL), and optional LLVM IR pipelines on small benign binaries to compare runtime and memory consumption for security research workflows.
This README aligns with the accompanying comparing analysis of IR design trade-offs (P-code, VEX, BIL, LLVM IR) and helps map empirical benchmarks to the paper's discussion of vulnerability discovery, malware triage, and deobfuscation tasks.

## 2. Safety warning (READ FIRST)

- **No malware is shipped**. Only benign samples are present.
- Handle any additional samples (especially malware) **inside an isolated VM / sandbox** with snapshots and no network bridge.
- You are responsible for sourcing malware safely (see `samples/MALWARE_SAMPLES_GO_HERE.txt`).

## 3. Repository layout

| Path | Purpose |
| --- | --- |
| `scripts/` | Automation scripts (`analyze_ghidra.sh`, `analyze_angr.py`, `analyze_bap.sh`, `analyze_llvm.sh`, `run_all.sh`) for all supported IR toolchains |
| `samples/benign/` | Benign example binaries |
| `samples/MALWARE_SAMPLES_GO_HERE.txt` | Placement instructions for user-provided malware |
| `results/` | Generated logs and summaries |
| `README.md` | Documentation (this file) |

## 4. Prerequisites

| Requirement | Notes |
| --- | --- |
| Ubuntu / Debian-like host | Tested mentally against Ubuntu 22.04 |
| Java 21+ | `sudo apt install openjdk-21-jdk` |
| Python 3.10+ | `sudo apt install python3 python3-venv python3-pip` |
| Virtualenv | `python3 -m venv .venv && source .venv/bin/activate` |
| angr | `pip install --upgrade pip angr` |
| Ghidra ≥ 10.x | Download <https://ghidra-sre.org/> and unzip (e.g., `/opt/ghidra`) |
| GNU time | `sudo apt install time` |
| BAP (optional) | Install via opam: `sudo apt install opam && opam init && opam install bap` |
| LLVM toolchain ≥ 15 (optional) | `sudo apt install llvm` or install from <https://releases.llvm.org/> |

## 5. Quick start

1. Clone the repo inside your analysis VM:  
   `git clone https://github.com/<you>/ir-benchmark-poc.git`
2. Enter the project and create a venv:  
   `cd ir-benchmark-poc && python3 -m venv .venv && source .venv/bin/activate`
3. Install Python deps:  
   `pip install --upgrade pip angr`
4. (Optional) Install BAP via opam if you plan to benchmark BIL IR:  

   ```bash
   sudo apt install opam
   opam init
   opam install bap
   eval $(opam env)
   ```

5. (Optional) Install LLVM 15+ binaries if you plan to benchmark an LLVM IR pipeline:  
   `sudo apt install llvm`
6. Download Ghidra and note its install path (e.g., `/opt/ghidra`).
7. Place benign samples in `samples/benign/`. Do **not** add malware to git.
8. Configure script paths (see below) and run `./scripts/run_all.sh`.

## 6. Script configuration

Edit variables at the top of each script or export them before running.

| Variable | Description | Example |
| --- | --- | --- |
| `GHIDRA_INSTALL_DIR` | Directory containing `ghidraRun` | `/opt/ghidra` |
| `PROJECT_DIR` | Absolute repo root | `/home/user/ir-benchmark-poc` |
| `SAMPLES_DIR` / `MALWARE_DIR` | Folder scanned for binaries | `"$PROJECT_DIR/samples/benign"` |
| `RESULTS_DIR` | Output directory | `"$PROJECT_DIR/results"` |
| `ENABLE_BAP` | Enable BAP/BIL analysis (true/false) | `true` |
| `ENABLE_LLVM` | Enable LLVM IR analysis (true/false) | `true` |

Inline overrides:  

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra PROJECT_DIR=$(pwd) ./scripts/run_all.sh
ENABLE_BAP=true ENABLE_LLVM=true ./scripts/run_all.sh  # Enable optional tools
```

## 7. Working with samples

- Benign binaries already live in `samples/benign/`.
- To test malware, follow the instructions inside `samples/MALWARE_SAMPLES_GO_HERE.txt`. Keep them **out of source control**.
- When transferring samples, prefer ISO images or shared folders attached only to the VM.

## 8. Running the benchmark

```bash
chmod +x scripts/*.sh
source .venv/bin/activate
GHIDRA_INSTALL_DIR=/opt/ghidra PROJECT_DIR=$(pwd) ./scripts/run_all.sh
```

To enable optional tools (BAP and/or LLVM):

```bash
ENABLE_BAP=true ENABLE_LLVM=true GHIDRA_INSTALL_DIR=/opt/ghidra ./scripts/run_all.sh
```

The wrapper:

- Launches Ghidra and angr analysis (always enabled), plus optional BAP and LLVM analysis helpers.
- Wraps each run with `time -v`.
- Writes raw logs plus parsed metrics to `results/`.

**Note on LLVM analysis:**

- For LLVM bitcode files, the script will disassemble to LLVM IR
- For native binaries, it provides LLVM-based disassembly and analysis
- For true binary-to-LLVM IR lifting, consider integrating [mcsema](https://github.com/lifting-bits/mcsema) or [remill](https://github.com/lifting-bits/remill)

## 9. Understanding results

- `results/analysis_results.log` — mixed raw + human-readable summary produced per run. Expect one block per configured tool (Ghidra / angr / BAP / LLVM IR).  
  Look for:
  - `Elapsed (wall clock) time` → total runtime.
  - `Maximum resident set size` → peak memory (KB).
- `results/summary.csv` (optional) — `sample,tool,elapsed_seconds,max_rss_kb`.
- Compare tools per sample by inspecting identical section headings.

The scripts **do not generate** CFG coverage, deobfuscation ratings, or similar qualitative scores. Those were manual metrics referenced in the companion paper.

## 10. Validation checklist

- [ ] Fresh VM with requirements installed.
- [ ] `GHIDRA_INSTALL_DIR` and friends configured.
- [ ] Benign executables available in `samples/benign/`.
- [ ] `./scripts/run_all.sh` completes without errors.
- [ ] Log files appear under `results/`.
- [ ] Parsed metrics show entries for every enabled tool (Ghidra, angr, and optionally BAP/LLVM).

## 11. Troubleshooting tips

- Missing Ghidra? Verify the install path and that `ghidraRun` is executable.
- Python import errors? Reactivate venv and reinstall angr.
- BAP not found? Ensure opam is initialized and BAP is installed: `opam install bap && eval $(opam env)`.
- LLVM not found? Install LLVM toolchain: `sudo apt install llvm` or download from <https://releases.llvm.org/>.
- Parsing failures? Confirm GNU time output is English and scripts still redirect stdout/stderr to the expected temp files.

## 12. Limitations & next steps

- Benchmarks only performance on small binaries; expand sample set for broader coverage.
- Resource usage varies by hardware and Ghidra project cache state.
- For richer metrics (CFG quality, detection scores), integrate additional tooling or manual review, leveraging insights from the comparative IR study to decide which IR best suits each task.

## 13. Contributing

- Submit PRs that respect safe-handling practices and avoid including malware.
- Document any new dependencies or configuration options.
