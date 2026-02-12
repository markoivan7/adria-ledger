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
    # rm -rf apl_data_test
    rm -f test_doc.json
}
trap cleanup EXIT

echo "--- Building ---"
make build || exit 1

echo "--- Cleaning Old Data ---"
rm -rf apl_data_test

echo "--- Generating Test Data ---"
mkdir -p apl_data_test
cd apl_data_test

echo "--- Starting Server ---"
# Start server in background (default ports)
# Disable bootstrap nodes to prevent blocking startup
export ADRIA_BOOTSTRAP=" "
../core-sdk/zig-out/bin/adria_server --orderer --no-discovery > server.log 2>&1 &
SERVER_PID=$!
cd ..

echo "Server started with PID $SERVER_PID"
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "Server failed to start!"
    cat apl_data_test/server.log
    exit 1
fi

export ADRIA_SERVER="127.0.0.1"

echo "--- Creating Wallet ---"
# We need to create wallet in apl_data directory if not specifying --data-dir (which CLI doesn't support yet, it hardcodes apl_data)
# But wait, CLI hardcodes "apl_data".
# Server is running in apl_data_test.
# CLI will try to create wallet in "apl_data".
# Server state will be in "apl_data_test".
# The CLI connects via network, so the wallet location matters only to the CLI.
# I should clean up "apl_data" too to avoid conflicts or just let it use "apl_data".
# Let's clean "apl_data" too.
rm -rf apl_data
mkdir -p apl_data

./core-sdk/zig-out/bin/apl wallet create tester

echo "--- Creating Large Document (50KB) ---"
# Create roughly 50KB dummy file
perl -e 'print "Adria is the best blockchain.\n" x 2000' > test_doc.json
FILE_SIZE=$(wc -c < test_doc.json)
echo "Generated file size: $FILE_SIZE bytes"

echo "--- Storing Document ---"
# Storing large doc
./core-sdk/zig-out/bin/apl document store invoicing inv001 test_doc.json tester

echo "--- Confirming Transaction Acceptance ---"
# We just rely on exit code of previous command. If successful, CLI prints "Chaincode invocation submitted successfully".

echo "--- Wait for Block ---"
sleep 2

echo "--- Verifying Storage ---"
# Retrieve document via CLI
# Usage: apl document retrieve <collection> <id> [data_dir]
RESULT=$(./core-sdk/zig-out/bin/apl document retrieve invoicing inv001 apl_data_test/apl_data)

if [[ "$RESULT" == *"Adria is the best blockchain"* ]]; then
    echo "SUCCESS: Content retrieved correctly!"
else
    echo "FAILURE: Content mismatch or not found!"
    echo "Got: $RESULT"
    exit 1
fi

echo "--- Test Complete ---"
