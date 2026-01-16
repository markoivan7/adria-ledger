# Adria Permissioned Ledger (APL) Makefile

ZIG := zig
PYTHON := python3
SDK_DIR := core-sdk
TEST_DIR := tests

.PHONY: all clean run test help

help:
	@echo "Adria Permissioned Ledger (PoC)"
	@echo "-------------------------------"
	@echo "make run    - Build and run the server (Orderer)"
	@echo "make test   - Run the end-to-end regression test (client)"
	@echo "make bench  - Run high-performance benchmarks"
	@echo "make kill   - Kill any running server instances"
	@echo "make clean  - Remove build artifacts and temporary data"
	@echo "make reset  - Full reset: Kill + Clean"

all: run

# Build only (Server + CLI)
build:
	@echo "Building Adria..."
	cd $(SDK_DIR) && $(ZIG) build

# Build and Run the Server
run:
	@echo "Building and Running Adria Server..."
	cd $(SDK_DIR) && $(ZIG) build run -- --orderer

# Run the Python Client Test
test:
	@echo "Running End-to-End Test (Asset Tracking Demo)..."
	cd $(SDK_DIR) && $(ZIG) build
	cd $(TEST_DIR) && ./demo_poc.sh

# Run the High-Performance Native Benchmark
bench:
	@sh tests/bench.sh

# Helper to kill running server instances
kill:
	@echo "Killing running server instances..."
	@-pkill -f "adria_server" || true
	@-pkill -f "make run" || true
	@echo "Done."

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf apl_data *.log
	rm -rf $(SDK_DIR)/zig-cache $(SDK_DIR)/zig-out $(SDK_DIR)/logs
	rm -rf $(SDK_DIR)/apl_data
	rm -rf $(TEST_DIR)/ledger.db $(TEST_DIR)/apl_data $(TEST_DIR)/*.log
	rm -rf $(TEST_DIR)/__pycache__
	@echo "Done."

# Reset everything (Kill + Clean)
reset: kill clean
	@echo "Environment reset complete. Ready for fresh 'make run'."
