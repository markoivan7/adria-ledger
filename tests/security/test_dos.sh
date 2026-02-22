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
    rm -f test_doc.json adria-config.json server.log
}
trap cleanup EXIT

echo "--- Building ---"
make build || exit 1

echo "--- Cleaning Old Data ---"
rm -rf apl_data adria-config.json server.log
mkdir -p apl_data

echo "--- Creating Identities ---"
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null

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

echo "--- Starting Server ---"
# Start server in background (default ports)
# Disable bootstrap nodes to prevent blocking startup
export ADRIA_BOOTSTRAP=" "
./core-sdk/zig-out/bin/adria_server --orderer --no-discovery > server.log 2>&1 &
SERVER_PID=$!

echo "Server started with PID $SERVER_PID"
echo "Waiting 2s for initialization..."
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null; then
    echo "Server failed to start!"
    cat server.log
    exit 1
fi

echo "--- Running DoS Tests (Python) ---"
python3 tests/security/test_dos.py

echo "--- Test Complete ---"
