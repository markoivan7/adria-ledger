#!/bin/bash
set -e

# Cleanup
echo "Cleaning up..."
pkill adria_server || true
rm -rf apl_data
rm -f ledger.db

# Start Server
echo "Starting APL Server..."
../core-sdk/zig-out/bin/adria_server --orderer > server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Create Wallet
echo "Creating Admin Wallet..."
../core-sdk/zig-out/bin/apl wallet create admin

# Run gl_app.py to Record Entry
echo "Recording Entry via Hybrid App..."
./gl_app.py record --debit "Expenses:Travel" --credit "Assets:Cash" --amount 150.00 --desc "Flight to NYC" --meta '{"flight":"UA123"}'

# Verify SQLite Status
echo "Checking SQLite Status..."
./gl_app.py list

# Verify manually if needed (the python script already verified, but we can double check)
# The python script prints "VERIFICATION SUCCESSFUL" if it works.

kill $SERVER_PID
echo "Test Complete"
