#!/bin/bash
set -e

# Cleanup
# Cleanup
echo "Cleaning up..."
pkill -f "adria_server" || true
# Kill Docker containers if running (prevent port conflict)
docker-compose -f ../../docker-compose.yml down 2>/dev/null || true

# Wait for it to actually die
count=0
while pgrep -f "adria_server" > /dev/null; do
    echo "Waiting for old server to stop..."
    sleep 1
    count=$((count+1))
    if [ $count -ge 5 ]; then
        echo "Forcing kill..."
        pkill -9 -f "adria_server"
        break
    fi
done

# Wait for port 10802 to be released (handle TIME_WAIT or Docker Proxy lag)
echo "Ensuring port 10802 is free..."
while nc -z localhost 10802 2>/dev/null; do
    echo "Waiting for port 10802 to be free..."
    sleep 1
done
rm -rf apl_data
rm -f ledger.db

# Start Server
echo "Starting APL Server..."
./core-sdk/zig-out/bin/adria_server --orderer > tests/functional/server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Create Wallet
echo "Creating Admin Wallet..."
./core-sdk/zig-out/bin/apl wallet create admin

# Run gl_app.py to Record Entry
echo "Recording Entry via Hybrid App..."
./tests/functional/gl_app.py record --debit "Expenses:Travel" --credit "Assets:Cash" --amount 150.00 --desc "Flight to NYC" --meta '{"flight":"UA123"}'

# Verify SQLite Status
echo "Checking SQLite Status..."
./tests/functional/gl_app.py list

# Verify manually if needed (the python script already verified, but we can double check)
# The python script prints "VERIFICATION SUCCESSFUL" if it works.

kill $SERVER_PID
echo "Test Complete"
