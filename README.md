# Adria Permissioned Ledger (APL)

> A lightweight, high-performance blockchain framework designed for enterprise use cases, featuring identity management, pluggable consensus, and a generic key-value world state.

---

## Overview

The **Adria Permissioned Ledger (APL)** is a modular blockchain framework built in **Zig**. Unlike permissionless blockchains that rely on energy-intensive Proof-of-Work and native currencies, APL is designed for known, trusted participants in a private network.

It provides a robust foundation for building decentralized applications that require:
*   **Identity & Permissioning**: Built-in Membership Service Provider (MSP) and Role-Based Access Control (RBAC).
*   **High Throughput**: Decoupled "Orderer" service for efficient block production.
*   **Finality**: Immediate transaction finality with leader-based consensus (Solo/Raft).
*   **Privacy**: Off-chain metadata storage with on-chain cryptographic anchoring.

## Key Features

*   **Lightweight Core**: Written in Zig for ease of deployment, low memory footprint, and high performance.
*   **Permissioned / MSP**: No anonymous keys. All participants (Admins, Writers, Readers) are identified via x509-style certificates (mocked for PoC).
*   **Modular Architecture**:
    *   **Consensus**: Pluggable interface supporting "Solo" (avail) and "Raft" (planned).
    *   **State**: Generic Key-Value store (World State) abstracted from the ledger logic.
    *   **Logic**: System Chaincodes for generic ledger recording and asset management.
*   **Fee-less**: No gas fees or native cryptocurrency. Spam is prevented via identity and rate limiting.
*   **Hybrid Storage**: "Side-DB" architecture allows rapid SQL querying (SQLite) while maintaining immutable proofs on the blockchain.

## Architecture

APL follows a modular design inspired by Hyperledger Fabric, separating the roles of **Ordering** and **Execution**.

| Component | Responsibility |
| :--- | :--- |
| **Client** (`cli.zig`) | Signs transactions, queries state, manages keys. |
| **Server** (`server.zig`) | Handles networking, RPCs, and the "Adria Protocol". |
| **Orderer** (`consensus/`) | Batches transactions into blocks and establishes total ordering. |
| **Peer** (`execution/`) | Validates blocks, executes chaincode, and updates the World State. |
| **State** (`db.zig`) | Persists the current state of the ledger (Key-Value pairs). |

### Core Components

#### 1. Entry Points
*   **`main.zig`**: The heart of the blockchain logic.
    *   **Orchestration**: Initializes the `ZeiCoin` struct, loads the database, and connects networking.
    *   **Consensus Engine**: Hosts the pluggable orderer (`Solo` or `Raft`).
    *   **Execution Sync Loop**: Background thread that polls for committed blocks and updates the state.
*   **`cli.zig`**: The Command Line Interface (`apl`).
    *   **User Interaction**: Handles commands like `wallet create`, `status`, `ledger record`.
    *   **Client Logic**: Connects to the server to submit transactions or query state.
*   **`server.zig`**: The Network Server (`adria_server`).
    *   **Listener**: Binds to TCP port (default 10802).
    *   **Protocol**: Handles the "Adria Protocol" (handshakes, transaction submission, block broadcasting).
    *   **RPC Handler**: Routes Raft RPCs (`RAFT_VOTE`, `RAFT_APPEND`) to the Consensus Engine.

#### 2. Execution Module (`core-sdk/execution/`)
*   **`db.zig`**: The Persistence Layer.
    *   **World State**: Manages the `state/` directory (Key-Value store).
    *   **Storage Abstraction**: Provides `put(key, val)` and `get(key)` wrapping the file system IO.
*   **`chaincode.zig`**: The Smart Contract Layer.
    *   **Interfaces**: Defines `Chaincode` and `Stub` traits for building contracts.
    *   **System Contracts**: Implements built-in logic like `GeneralLedger` (KV Store) and `AssetLedger` (Mint/Transfer).
*   **`acl.zig`**: Access Control Lists.
    *   **Permissions**: Defines `Role` enums (Admin, Writer, Reader).
    *   **Enforcement**: Checking if a specific wallet address has the right to execute a function.

#### 3. Consensus Module (`core-sdk/consensus/`)
*   **`mod.zig`**: The Interface.
    *   Defines `Consenter` struct with VTable (Start, Stop, RecvTransaction).
    *   Allows `main.zig` to be agnostic of the ordering mechanism.
*   **`solo.zig`**: Single Node Orderer.
    *   Simple batching logic (size/time triggers).
*   **`raft.zig`**: Distributed Consensus (Planned).

### Data Flow
1.  **Client (`cli.zig`)** signs a Tx (`wallet.zig`) → Sends to **Server (`server.zig`)**.
2.  **Server** passes Tx to **Orderer (`main.zig`)**.
3.  **Orderer** batches Tx into a **Block (`types.zig`)**.
4.  **Orderer** commits Block → Calls **Execution Engine (`main.zig`)**.
5.  **Execution Engine** invokes **Chaincode (`chaincode.zig`)**.
6.  **Chaincode** updates **World State (`db.zig`)** via `Stub`.

## Directory Structure

*   `core-sdk/` - The main Zig implementation (Node, CLI, SDK).
    *   `common/` - Shared types and utilities.
    *   `execution/` - State machine, DB, and Chaincode.
    *   `consensus/` - Ordering logic.
    *   `network/` - P2P networking and serialization.
    *   `crypto/` - Cryptographic primitives.
*   `tests/` - Integration tests and Python client SDK.

### Quick Start

#### 1. Prerequisites
*   **Zig**: Version **0.13.0** or newer. ([Download](https://ziglang.org/download/))
*   **Python 3**: Required for the client demo scripts.

#### 2. Clone the Repository
```bash
git clone https://github.com/Maril-Systems/adria-ledger.git
cd adria-ledger
```

#### 3. Build the Project
Use the provided `Makefile` to build both the Server and CLI:
```bash
make build
```

Or manually:
```bash
cd core-sdk
zig build
```

#### 4. Automated Quick Start
Run the full end-to-end demo (starts server, mints assets, transfers them, and verifies state) in one command:
```bash
make test
```

#### 5. Manual Operation
For manual testing, you will need **two terminal windows**.

**Terminal 1: Start the Server**
```bash
make run
```
*The server will start on localhost (P2P: 10801, API: 10802). Keep this terminal open.*

**Terminal 2: Run CLI Commands**
The CLI tool `apl` is available in `core-sdk/zig-out/bin/`.

**Check the help menu:**
```bash
./core-sdk/zig-out/bin/apl --help
```

**Example Commands:**
```bash
# Get blockchain status
./core-sdk/zig-out/bin/apl status

# Create a new local wallet
./core-sdk/zig-out/bin/apl wallet create mywallet

# Record data to the ledger
./core-sdk/zig-out/bin/apl ledger record invoice:001 "{\"amount\": 500, \"item\": \"Laptop\"}" mywallet
```

## License

Open Source.
