# IR Lifting Benchmark Report

## Executive Summary

This report summarizes the performance and reliability of IR lifting tools across different architectures.

## Aggregate Performance by Tool & Architecture

| Tool | Architecture | Success Rate | Avg Time (s) | Avg Mem (MB) | Avg Blocks | Avg IR Stmts |
|---|---|---|---|---|---|---|
| angr | x86-64 | 100.0% (574/574) | 0.98 | 114.70 | 212.3 | 3341.8 |
| ghidra | x86-64 | 100.0% (574/574) | 7.03 | 616.92 | 16.4 | 58.8 |
| llvm | x86-64 | 100.0% (574/574) | 0.01 | 10.10 | 0.0 | 800.4 |

## Practicality Gap Analysis

Comparison of operational readiness (Success Rate) between tools.

| Tool | Overall Success Rate |
|---|---|
| angr | 100.0% (574/574) |
| ghidra | 100.0% (574/574) |
| llvm | 100.0% (574/574) |