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
# Run all test suites
test:
	@echo "Running all tests..."
	make test-core
	make test-cli
	make test-document
	make test-reconstruct
	make test-security
	make test-offline
	make test-governance
	make bench
	@echo "All tests passed!"
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
test-core:
	@echo "Running General Ledger PoC..."
	cd $(SDK_DIR) && $(ZIG) build
	@sh tests/functional/verify_gl_app.sh

# Run the Asset Ledger Demo (Optional)
test-asset:
	@echo "Running Asset Ledger Demo..."
	cd $(SDK_DIR) && $(ZIG) build
	@sh tests/demos/demo_poc.sh

# Run the CLI Command Suite
test-cli:
	@echo "Running CLI Verification Suite..."
	cd $(SDK_DIR) && $(ZIG) build
	@bash tests/functional/test_cli_suite.sh

# Run State Reconstruction Verification
test-reconstruct:
	@echo "Running State Reconstruction Test (Auditability)..."
	@bash tests/functional/reconstruct_test.sh

# Run the High-Performance Native Benchmark
bench:
	@sh tests/benchmarks/bench.sh

# Run the benchmark against Docker cluster
bench-docker:
	@sh tests/benchmarks/bench_docker.sh

# Run Functional Tests against Docker Cluster
test-docker:
	@echo "Running Functional Tests against Docker Cluster..."
	@chmod +x tests/functional/test_docker.sh
	@./tests/functional/test_docker.sh

# Run Document Store Verification (Large Payloads)
test-document:
	@echo "Running Document Store Verification..."
	@bash tests/functional/test_document_store.sh

test-offline:
	@echo "Running Offline Signing Verification..."
	cd $(SDK_DIR) && $(ZIG) build
	@bash tests/functional/test_offline_signing.sh

# Run Security Verification (DoS, etc.)
test-security:
	@echo "Running Security Verification Suite..."
	@chmod +x tests/security/test_dos.sh
	@./tests/security/test_dos.sh

# Run Governance Tests (Unit Tests)
test-governance:
	@echo "Running Governance Unit Tests..."
	cd $(SDK_DIR) && $(ZIG) build test

# Helper to kill running server instances
kill:
	@echo "Killing running server instances..."
	@-pkill -f "adria_server" || true
	@-pkill -f "make run" || true
	@# robust wait loop
	@count=0; while pgrep -f "adria_server" > /dev/null; do \
		echo "Waiting for shutdown..."; \
		sleep 1; \
		count=$$((count+1)); \
		if [ $$count -ge 5 ]; then \
			echo "Forcing kill..."; \
			pkill -9 -f "adria_server"; \
			break; \
		fi; \
	done
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

# Clean Docker resources (Containers + Volumes)
clean-docker:
	@echo "Cleaning Docker cluster..."
	docker-compose down -v --remove-orphans

# Reset everything (Kill Local + Clean + Docker Down)
reset-all: kill clean clean-docker

# Alias for reset-all
nuke: reset-all
	@echo "ADRIA NUKE COMPLETE (All Clean)"

# Reset everything (Kill + Clean)
reset: kill clean
	@echo "Environment reset complete. Ready for fresh 'make run'."
