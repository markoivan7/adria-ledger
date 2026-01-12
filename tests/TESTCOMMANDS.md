================================================================================
TEST 1: FULL END-TO-END DEMO (Asset Tracking)
Goal: Verify Server, Wallets, and Asset Chaincode (Mint/Transfer)
================================================================================

# 1. Switch to the tests directory
cd tests

# 2. Run the automated demo script
# This will:
# - Clean up old data
# - Start the APL Server (Orderer Mode)
# - Create Admin/Bob wallets
# - Mint an Asset to Admin
# - Transfer Asset to Bob
# - Verify ownership via Ledger State
./demo_poc.sh

# (Wait for "SUCCESS: Asset is owned by Bob!" message)


================================================================================
TEST 2: HYBRID GENERAL LEDGER (SQLite + Blockchain Anchor)
Goal: Record Journal Entries in SQLite and Anchor Hash to APL Blockchain
================================================================================

# 1. Switch to the tests directory (if not already there)
cd tests

# 2. Clean up previous test data (Optional, for a fresh start)
rm ledger.db
rm -rf apl_data
pkill adria_server

# 3. Start the Server manually
# We start it in the background (&) and log output to server.log
../core-sdk/zig-out/bin/adria_server --orderer > server.log 2>&1 &

# 4. Create an Admin wallet (Required to sign transactions)
../core-sdk/zig-out/bin/apl wallet create admin

# 5. Record Entry #1 (Expense)
# This saves to SQLite AND sends a hash anchor to the blockchain
./gl_app.py record --debit Equipment --credit Cash --amount 1500.00 --desc "Dell PowerEdge Server"

# 6. Record Entry #2 (Revenue)
./gl_app.py record --debit Cash --credit ServiceRevenue --amount 5000.00 --desc "Q4 Deployment Contract"

# 7. List Entries
# Verifies data is stored locally
./gl_app.py list

# 8. (Optional) Inspect the APL Blockchain State
# You can see the hashes stored in the 'mpl_data/state' directory (filenames are hex keys)
ls -l apl_data/state/

# 9. Cleanup (Stop the server)
pkill adria_server
