#!/bin/bash
export ADRIA_WALLET_PASSWORD=testpassword
set -e

echo "====================================="
echo "  Testing Dataset Store (Phase 19)"
echo "====================================="

DATA_DIR="apl_data"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/wallets"

# Build
echo "[1] Building..."
make build

export ADRIA_SERVER="127.0.0.1"
API_PORT=8083

echo "[2] Creating Identities..."
./core-sdk/zig-out/bin/apl wallet create tester > /dev/null
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null

./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca tester > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)

# Cleanup and setup config
cat <<EOF > adria-config.json
{
  "network": {
    "api_port": $API_PORT,
    "p2p_port": 9003,
    "max_connections": 50,
    "connection_timeout_ms": 5000,
    "network_id": 1
  },
  "consensus": {
    "block_interval_ms": 1000,
    "max_transactions_per_block": 2000,
    "batch_timeout_ms": 200,
    "mode": "solo",
    "role": "orderer",
    "seed_root_ca": "$ROOT_PUBKEY"
  },
  "storage": {
    "data_dir": "$DATA_DIR"
  }
}
EOF

# Start Server
echo "[3] Starting Server..."
./core-sdk/zig-out/bin/adria_server --orderer > server_dataset.log 2>&1 &
SERVER_PID=$!
sleep 2

# Prepare data chunks
cat <<EOF > chunk1.json
[
  {"_id": "row1", "name": "Alice", "age": 30},
  {"_id": "row2", "name": "Bob", "age": 40}
]
EOF

cat <<EOF > chunk2.json
[
  {"_id": "row3", "name": "Charlie", "age": 50}
]
EOF

echo "[4] Appending chunks for snapshot_v1..."
# Append chunk 1
./core-sdk/zig-out/bin/apl dataset append dataset1 snap_v1 chunk1.json tester
sleep 2

# Append chunk 2
./core-sdk/zig-out/bin/apl dataset append dataset1 snap_v1 chunk2.json tester
sleep 2

echo "[5] Committing snapshot_v1..."
./core-sdk/zig-out/bin/apl dataset commit dataset1 snap_v1 '{"version": 1}' tester
sleep 2

echo "[6] Querying dataset current dataset1 (snap_v1)..."
./core-sdk/zig-out/bin/apl dataset current dataset1 "$DATA_DIR" > current_v1.json
cat current_v1.json
if ! grep -q '"age":30' current_v1.json; then
    echo "FAILED to find Alice in current_v1"
    kill $SERVER_PID
    exit 1
fi

echo "[7] Preparing new data for snapshot_v2..."
# Snap 2: Bob age updated (Modified), Alice removed (Removed), Dave appended (Added)
cat <<EOF > chunk3_v2.json
[
  {"_id": "row2", "name": "Bob", "age": 41},
  {"_id": "row3", "name": "Charlie", "age": 50},
  {"_id": "row4", "name": "Dave", "age": 20}
]
EOF

# Append chunk 1 for v2
./core-sdk/zig-out/bin/apl dataset append dataset1 snap_v2 chunk3_v2.json tester
sleep 2

# Commit v2
echo "[8] Committing snapshot_v2..."
./core-sdk/zig-out/bin/apl dataset commit dataset1 snap_v2 '{"version": 2, "parent_snapshot_id": "snap_v1"}' tester
sleep 2

echo "[9] Querying dataset history..."
./core-sdk/zig-out/bin/apl dataset history dataset1 "$DATA_DIR" > history.txt
cat history.txt
if ! grep -q "snap_v1" history.txt; then
    echo "FAILED to find snap_v1 in history"
    kill $SERVER_PID
    exit 1
fi

echo "[10] Querying dataset diff (snap_v1 -> snap_v2)..."
./core-sdk/zig-out/bin/apl dataset diff snap_v1 snap_v2 "$DATA_DIR" > diff.json
cat diff.json

if ! grep -q 'Dave' diff.json; then
    echo "FAILED diff output: Missing Added (Dave)"
    kill $SERVER_PID
    exit 1
fi
if ! grep -q 'Alice' diff.json; then
    echo "FAILED diff output: Missing Removed (Alice)"
    kill $SERVER_PID
    exit 1
fi
if ! grep -q '41' diff.json; then
    echo "FAILED diff output: Missing Modified (Bob 41)"
    kill $SERVER_PID
    exit 1
fi

echo ""
echo "====================================="
echo "  [SUCCESS] Dataset test passed!"
echo "====================================="

# Cleanup
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
rm chunk1.json chunk2.json chunk3_v2.json current_v1.json history.txt diff.json
rm -rf "$DATA_DIR"
