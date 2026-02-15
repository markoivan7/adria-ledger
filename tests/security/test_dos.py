import socket
import time
import threading
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 10802
MAX_CONNECTIONS = 100

def test_max_connections():
    print(f"--- Testing MAX_CONNECTIONS ({MAX_CONNECTIONS}) ---")
    sockets = []
    try:
        # 1. Fill up connections
        print(f"Opening {MAX_CONNECTIONS} connections...")
        for i in range(MAX_CONNECTIONS):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            sockets.append(s)
            if i % 10 == 0:
                print(f"Connected: {i+1}", end="\r")
        print(f"\nEstablished {len(sockets)} connections.")

        # 2. Try to exceed limit
        print("Attempting to exceed limit...")
        try:
            s_extra = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_extra.settimeout(2.0) # Short timeout for rejection
            s_extra.connect((SERVER_IP, SERVER_PORT))
            
            # Try to read. Server should close it immediately or not accept data?
            # Implementation says: close() and continue.
            # So recv should return 0 bytes (EOF) or connection reset.
            data = s_extra.recv(1024)
            if not data:
                print("SUCCESS: Extra connection closed by server (EOF).")
            else:
                print(f"FAILURE: Extra connection received data: {data}")
                return False
                
            s_extra.close()
        except (ConnectionResetError, BrokenPipeError):
            print("SUCCESS: Extra connection reset by server.")
        except socket.timeout:
            print("FAILURE: Extra connection timed out (Server kept it open?).")
            return False

    except Exception as e:
        print(f"ERROR during max connection test: {e}")
        return False
    finally:
        print("Closing all connections...")
        for s in sockets:
            s.close()
    
    return True

def test_read_timeout():
    print("\n--- Testing Read Timeout (5s) ---")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        print("Connected. Sleeping for 2 seconds (Should stay alive)...")
        time.sleep(2)
        
        # Check if alive (send PING)
        s.sendall(b"PING\n")
        response = s.recv(1024)
        if b"PONG" not in response:
            print(f"FAILURE: Connection died prematurely? Got: {response}")
            return False
        print("Alive check passed.")
        
        # Now reconnect and sleep for 6+ seconds
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        
        print("Connected. Sleeping for 7 seconds (Should be killed)...")
        # We don't send anything. Server should timeout waiting for read.
        # Wait, the timeout is on `read` operation.
        # If the client sends NOTHING, the server `read` blocks until timeout.
        # Then server closes.
        
        time.sleep(7)
        
        # Now try to write/read. Should fail.
        try:
            s.sendall(b"PING\n")
            data = s.recv(1024)
            if not data:
                print("SUCCESS: Connection closed by server (EOF).")
                return True
            else:
                print(f"FAILURE: Connection still alive! Got: {data}")
                return False
        except (ConnectionResetError, BrokenPipeError):
            print("SUCCESS: Connection reset (Closed by server).")
            return True
            
    except Exception as e:
        print(f"ERROR: {e}")
        return False
    finally:
        s.close()

if __name__ == "__main__":
    success = True
    
    if not test_max_connections():
        success = False
        
    # Wait for server to cleanup sockets from first test
    time.sleep(2)
        
    if not test_read_timeout():
        success = False
        
    if success:
        print("\n[PASS] All DoS tests passed.")
        sys.exit(0)
    else:
        print("\n[FAIL] Some tests failed.")
        sys.exit(1)
