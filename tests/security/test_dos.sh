#!/bin/bash
set -e

# Setup
SERVER_PID=""

# Define cleanup
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        echo "Killing server PID $SERVER_PID"
        kill $SERVER_PID || true
    fi
    rm -f test_doc.json
}
trap cleanup EXIT

echo "--- Building ---"
make build || exit 1

echo "--- Cleaning Old Data ---"
rm -rf apl_data_test_dos
mkdir -p apl_data_test_dos
cd apl_data_test_dos

echo "--- Starting Server ---"
# Start server in background (default ports)
# Disable bootstrap nodes to prevent blocking startup
export ADRIA_BOOTSTRAP=" "
../core-sdk/zig-out/bin/adria_server --orderer --no-discovery > server.log 2>&1 &
SERVER_PID=$!
cd ..

echo "Server started with PID $SERVER_PID"
echo "Waiting 2s for initialization..."
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "Server failed to start!"
    cat apl_data_test_dos/server.log
    exit 1
fi

echo "--- Running DoS Tests (Python) ---"
python3 tests/security/test_dos.py

echo "--- Test Complete ---"
