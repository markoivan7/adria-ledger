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
    rm -rf apl_data adria-config.json server.log
    rm -f test_doc.json
}
trap cleanup EXIT

echo "--- Building ---"
make build || exit 1

echo "--- Cleaning Old Data ---"
rm -rf apl_data adria-config.json server.log
mkdir -p apl_data

echo "--- Creating Identities ---"
./core-sdk/zig-out/bin/apl wallet create tester > /dev/null
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null

./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca tester > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)
echo "Root PK: $ROOT_PUBKEY"

cat <<EOF > adria-config.json
{
    "network": {
        "p2p_port": 10801,
        "api_port": 10802,
        "discovery": true,
        "seeds": [],
        "network_id": 1
    },
    "storage": {
        "data_dir": "apl_data",
        "log_level": "info"
    },
    "consensus": {
        "mode": "solo",
        "role": "orderer",
        "seed_root_ca": "$ROOT_PUBKEY"
    }
}
EOF

export ADRIA_BOOTSTRAP=" "
./core-sdk/zig-out/bin/adria_server --orderer --no-discovery > server.log 2>&1 &
SERVER_PID=$!

echo "Server started with PID $SERVER_PID"
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "Server failed to start!"
    cat server.log
    exit 1
fi

export ADRIA_SERVER="127.0.0.1"


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
RESULT=$(./core-sdk/zig-out/bin/apl document retrieve invoicing inv001 apl_data)

if [[ "$RESULT" == *"Adria is the best blockchain"* ]]; then
    echo "SUCCESS: Content retrieved correctly!"
else
    echo "FAILURE: Content mismatch or not found!"
    echo "Got: $RESULT"
    exit 1
fi

echo "--- Test Complete ---"
