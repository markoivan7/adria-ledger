#!/bin/bash

# Adria Benchmarking Runner

echo "=========================================="
echo "    Adria Ledger Benchmarking Suite       "
echo "=========================================="

# Ensure we are in project root (if run from tests/benchmarks/run.sh)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_ROOT="$SCRIPT_DIR/../.."

echo "Project Root: $PROJECT_ROOT"
cd "$PROJECT_ROOT"

# 1. Micro Benchmarks
echo ""
echo ">>> Running Micro-Benchmarks (Zig)..."
echo "------------------------------------------"

echo "[1/2] Consensus Ingestion..."
zig run core-sdk/bench_consensus.zig

echo ""
echo "[2/2] Crypto Operations..."
zig run core-sdk/bench_crypto.zig

# 2. Macro Benchmarks
echo ""
echo ">>> Running Macro-Benchmarks (Python)..."
echo "------------------------------------------"

# check if server is running
if pgrep -x "adria_server" > /dev/null
then
    echo "Adria Server detected running."
    echo "Running Spam Benchmark..."
    python3 tests/benchmarks/macro/spam_tx.py
else
    echo "Skipping Spam Benchmark (Adria Server not running)."
    echo "Tip: Run 'make run' in a separate terminal to enable E2E testing."
fi

echo ""
echo "=========================================="
echo "Benchmarking Complete."
