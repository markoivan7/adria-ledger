import socket
import time
import os
import sys
import threading
import json
import subprocess

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT_API = 10802
NUM_TRANSACTIONS = 1000
CONCURRENCY = 10

def get_apl_binary():
    # Assume we are running from project root or tests/benchmarks
    # Try finding the binary in standard location
    paths = [
        "../../../core-sdk/zig-out/bin/apl",
        "../../core-sdk/zig-out/bin/apl",
        "./core-sdk/zig-out/bin/apl"
    ]
    for p in paths:
        if os.path.exists(p):
            return os.path.abspath(p)
    return None

def create_wallet(apl_bin, name):
    # This is a bit slow because it shells out, but we only do it once
    subprocess.run([apl_bin, "wallet", "create", name], capture_output=True)

def spam_worker(worker_id, num_tx, apl_bin, wallet_name):
    # For maximum speed, we should probably construct raw TCP packets
    # But for now, let's shell out to 'apl ledger record' to simulate "Client CLI" load
    # Note: Shelling out 1000 times is slow (process overhead). 
    # A real spammer would import the python SDK if available, or write raw socket code.
    # Given the constraints, let's write raw socket code to bypass CLI overhead!
    
    # Actually, constructing a valid Adria Transaction in raw Python requires Ed25519 signing.
    # To keep this script simple and dependency-free (standard lib only), 
    # we might be stuck with CLI or need to pip install ed25519.
    # Let's try the CLI approach first. If it's too slow (measuring process fork speed vs blockchain),
    # we'll know.
    
    for i in range(num_tx):
        subprocess.run([
            apl_bin, "ledger", "record", f"bench-{worker_id}-{i}", f"value-{i}", wallet_name
        ], capture_output=True)

def main():
    print(f"=== Adria Macro-Benchmark: {NUM_TRANSACTIONS} Tx ===")
    
    apl_bin = get_apl_binary()
    if not apl_bin:
        print("Error: Could not find 'apl' binary. Did you run 'make build'?")
        sys.exit(1)
        
    print(f"Using binary: {apl_bin}")
    
    # Create a bench wallet
    wallet_name = "bench_wallet"
    create_wallet(apl_bin, wallet_name)
    
    start_time = time.time()
    
    threads = []
    tx_per_thread = NUM_TRANSACTIONS // CONCURRENCY
    
    print(f"Starting {CONCURRENCY} threads sending {tx_per_thread} txs each...")
    
    for i in range(CONCURRENCY):
        t = threading.Thread(target=spam_worker, args=(i, tx_per_thread, apl_bin, wallet_name))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    end_time = time.time()
    duration = end_time - start_time
    tps = NUM_TRANSACTIONS / duration
    
    print(f"\n--- Results ---")
    print(f"Total Transactions: {NUM_TRANSACTIONS}")
    print(f"Total Time:         {duration:.2f} s")
    print(f"Effective TPS:      {tps:.2f}")
    print(f"Note: This measures TPS including CLI process overhead.")

if __name__ == "__main__":
    main()
