#!/bin/bash
set -e

# Cleanup
pkill zen_server || true
sleep 1
rm -rf zeicoin_data

# Start Server in background
echo "🚀 Starting Zen Server (Orderer Mode)..."
../core-sdk/zig-out/bin/zen_server --orderer > server.log 2>&1 &
SERVER_PID=$!
echo "Waiting for server to start..."
sleep 3

# Client Operations
echo "👤 Creating Wallet..."
../core-sdk/zig-out/bin/zeicoin wallet create alice

# Funding removed in Phase 5 (Fee-less)
# echo "💰 Funding Wallet..."
# ../core-sdk/zig-out/bin/zeicoin fund alice

echo "📝 Recording Ledger Entry..."
# Note: "invoice:123"
../core-sdk/zig-out/bin/zeicoin ledger record "invoice:123" "{\"item\":\"Server\",\"cost\":5000}" alice

echo "⏳ Waiting for Block Production (5s)..."
sleep 5

echo "✅ Verification: Checking State File..."
if command -v xxd >/dev/null 2>&1; then
    KEY_HEX=$(printf "invoice:123" | xxd -p | tr -d '\n')
else
    KEY_HEX="696e766f6963653a313233"
fi

STATE_FILE="zeicoin_data/state/$KEY_HEX"

if [ -f "$STATE_FILE" ]; then
    CONTENT=$(cat "$STATE_FILE")
    echo "📄 Found State File: $STATE_FILE"
    echo "📄 Content: $CONTENT"
    
    EXPECTED="{\"item\":\"Server\",\"cost\":5000}"
    if [ "$CONTENT" == "$EXPECTED" ]; then
        echo "✅ SUCCESS: Data matches!"
    else
        echo "❌ FAILURE: Content mismatch!"
        echo "Expected: $EXPECTED"
        echo "Got: $CONTENT"
    fi
else
    echo "❌ FAILURE: State file not found at $STATE_FILE"
    echo "Listing state directory:"
    ls -la zeicoin_data/state/ || echo "State dir not found"
    
    echo "📜 Server Log Tail:"
    tail -n 20 server.log
fi

# Cleanup
echo "🛑 Stopping Server..."
kill $SERVER_PID || true
