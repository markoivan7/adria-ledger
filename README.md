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
    *   **Logic**: System Chaincodes for generic ledger recording, asset management, and **generic document storage**.
*   **Schema-Agnostic**: Support for rich 64KB JSON payloads via the `DocumentStore` chaincode.
*   **Fee-less**: No gas fees or native cryptocurrency. Spam is prevented via identity and rate limiting.
*   **Cryptography**: High-performance primitives (Ed25519 for signatures, BLAKE3 for content hashing) with **Parallel Verification**.
*   **Event Sourcing**: The Blockchain is the immutable Write-Ahead Log (WAL). The State (SQL/KV) is a disposable View that can be fully reconstructed from the chain.

## Architecture

Adria implementation follows a strict **Event Sourcing** pattern, separating the **Immutable Log** (Truth) from the **Mutable State** (View).

### Why Adria?
Unlike standard databases where deleting a file destroys history, Adria provides **Reconstructible State**:
1.  **Truth (The Chain)**: Every transaction is cryptographically signed and appended to the immutable log (`blocks/`). This is the single source of truth.
2.  **View (The State)**: The "World State" (`state/`) is merely a cached projection of the chain.
    - **Performance**: You query the State for millisecond-latency reads.
    - **Safety**: If the State is corrupted or deleted, Adria can **Rehydrate** it by replaying the Chain from Block 0.
    - **Reconstructability**: You can rebuild the state on a fresh machine to cryptographically verify the entire history.

### Data Design: The Hybrid Model
Adria supports **On-Chain Storage** for business data, but you should follow the Hybrid Model:

1.  **On-Chain (Public/Shared)**:
    *   **Business Logic State**: Status codes (`APPROVED`, `PENDING`), identifiers, ownership records, and state transitions.
    *   **Metadata**: key-values, timestamps, author signatures, and process tags.
    *   **Small Documents**: JSON configuration objects and lightweight structured data (up to 64KB).
    *   *Why?* **Reconstructible**. This data is immutable and forever part of the ledger. If you lose your database, `apl hydrate` will restore it from the chain history.

2.  **Off-Chain (Private)**:
    *   **Large Files**: PDF Invoices, High-Res Photos.
    *   **Sensitive Data**: PII (Names, Addresses), Trade Secrets.
    *   *How?* Store the file locally, calculate its **BLAKE3 hash**, and store **only the hash** on-chain.
    *   *Warning*: **Not Reconstructible**. The chain only holds the fingerprint. You are responsible for backing up the actual files. If you lose the file, the chain cannot restore it.

### Modular Components
| Component | Responsibility |
| :--- | :--- |
| **Client** (`cli.zig`) | Signs transactions, queries state, manages keys. |
| **Server** (`server.zig`) | Handles networking, RPCs, and the "Adria Protocol". |
| **Orderer** (`consensus/`) | Batches transactions into blocks (The WAL). |
| **Peer** (`execution/`) | Validates blocks and updates the World State (The View). |

### Data Flow (Lifecycle of an Event)
1.  **Client (`cli.zig`)** creates a payload, signs it with a `wallet`, and sends a `Transaction` to the **Server**.
2.  **Server (`server.zig`)** validates the protocol header and forwards the Tx to the **Consensus Engine (`main.zig`)**.
3.  **Orderer** batches the Tx into a **Block**, timestamps it, and appends it to the immutable ledger (`blocks/`).
4.  **Orderer** broadcasts the committed Block to the **Execution Engine**.
5.  **Execution Engine** verifies the Block signature and sequentially applies transactions to the **Chaincode (`chaincode.zig`)**.
6.  **Chaincode** updates the **World State (`db.zig`)**, which the Client can then query instantly.

### State Reconstruction
Adria includes a tool, `apl hydrate`, to rebuild the state.

*   **Fast Mode (Default)**: Replays blocks to rebuild state, checking hash continuity chains (Trust-On-First-Use). Fast state recovery.
*   **Audit Mode (`--verify-all`)**: Re-verifies **every cryptographic signature** on every transaction in history. This provides a mathematical guarantee that the current state is the result of valid, authorized transactions.

This allows verification of the ledger's integrity without relying on the current database state.

### 1. Entry Points
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

### 2. Execution Module (`core-sdk/execution/`)
*   **`db.zig`**: The Persistence Layer.
    *   **World State**: Manages the `state/` directory using a custom **Bitcask** engine (Append-Only Log).
    *   **Storage Abstraction**: Provides O(1) `put(key, val)` and `get(key)` via in-memory indexing.
*   **`chaincode.zig`**: The Smart Contract Layer.
    *   **Interfaces**: Defines `Chaincode` and `Stub` traits for building contracts.
    *   **System Contracts**: Implements built-in logic like `GeneralLedger` (KV Store) and `AssetLedger` (Mint/Transfer).
*   **`acl.zig`**: Access Control Lists.
    *   **Permissions**: Defines `Role` enums (Admin, Writer, Reader).
    *   **Enforcement**: Checking if a specific wallet address has the right to execute a function.

### 3. Consensus Module (`core-sdk/consensus/`)
*   **`mod.zig`**: The Interface.
    *   Defines `Consenter` struct with VTable (Start, Stop, RecvTransaction).
    *   Allows `main.zig` to be agnostic of the ordering mechanism.
*   **`solo.zig`**: Single Node Orderer.
    *   Simple batching logic (size/time triggers).
*   **`raft.zig`**: Distributed Consensus (Planned).

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
*   **Zig**: Version **0.13.0** to **0.14.0-dev**.
*   **Docker Desktop**: Required for multi-node simulation and containerized benchmarking.
*   **Python 3**: Required for the client demo scripts.

#### 2. Clone the Repository
```bash
git clone https://github.com/markoivan7/adria-ledger.git
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

#### 4. Verify Installation
Run the General Ledger PoC to ensure everything is working:
```bash
make test
```

## Test Suite & Demos

Adria includes several pre-built scenarios to verify functionality.

### 1. General Ledger PoC (Functional Integrity)
**Goal:** Verify the integrity of the ledger and the hybrid storage model.
*   **What it does:** Simulates a client recording data, validates cryptographic anchors, and ensures the World State matches the blockchain history.
*   **Command:**
    ```bash
    make test
    ```

### 2. Asset Transfer Demo (Business Logic)
**Goal:** Demonstrate the `AssetLedger` system chaincode.
*   **What it does:** Mints new assets to an admin wallet and performs transfers between users, verifying balances at each step.
*   **Command:**
    ```bash
    make test-asset
    ```

### 3. Reconstructability Test
**Goal:** Verify that the "World State" can be completely deleted and faithfully reconstructed from the blockchain history.
*   **What it does:** Generates transactions, deletes the state database, and runs `apl hydrate` to rebuild it, confirming bit-for-bit identity.
*   **Command:**
    ```bash
    make test-reconstruct
    ```

### 4. Document Store (Large Payload)
**Goal**: Verify storage and retrieval of large documents (up to 60KB).
*   **What it does**: Stores a 50KB+ file on-chain and verifies state persistence.
*   **Command**:
    ```bash
    make test-document
    ```


## Performance Benchmarking

Measure throughput and latency under high load.

### 1. Local Benchmark (Single Node)
**Goal:** Test raw ingestion speed and execution efficiency (Leader Mode).
*   **Environment:** Single local process (Release Mode) on Apple Silicon.
*   **Configuration:** 2000 Tx Batch.
*   **Command:**
    ```bash
    make bench
    ```

### 2. Docker Cluster Benchmark (Multi-Node)
**Goal:** Simulate a realistic production network with 3 nodes (Orderer + 2 Peers).
*   **Environment:** Docker Containers (Alpine Linux).
*   **Validation:** Verifies propagation, consensus, parallel verification, and end-to-end finality.
*   **Command:**
    ```bash
    make bench-docker
    ```

## Manual Development Mode

For interactive testing, you can run the server and CLI manually.

**1. Start the Server**
```bash
make run
```
*Starts Orderer on localhost (P2P: 10801, API: 10802).*

**2. Run CLI Commands**
Open a new terminal:
```bash
# Check status
./core-sdk/zig-out/bin/apl status

# Create wallet
./core-sdk/zig-out/bin/apl wallet create mywallet

# Record data
./core-sdk/zig-out/bin/apl ledger record invoice:001 "{\"amt\": 500}" mywallet
```

### CLI Command Reference

The `apl` binary (`./core-sdk/zig-out/bin/apl`) supports the following commands:

| Domain | Command | Description |
| :--- | :--- | :--- |
| **Wallet** | `wallet create [name]` | Generating a new Ed25519 keypair and saving it to `apl_data/wallets`. |
| | `wallet load [name]` | Verifying that an existing wallet can be loaded. |
| | `wallet list` | Listing all available local wallets. |
| **Network** | `status` | Querying the server for current block height and sync status. |
| | `address [wallet]` | Displaying the address (hex) of a specific wallet. |
| **Ledger** | `ledger record <key> <val>` | Submitting a generic data entry to the blockchain. |
| | `ledger query <key>` | Querying the state for a specific key (Proof of Existence). |
| **Documents** | `document store <collection> <id> <file>` | Storing a large document (up to 60KB) on-chain. |
| | `document retrieve <collection> <id>` | Retrieving a stored document from the local state. |
| **Reconstruction** | `hydrate` | Reconstructs the World State from the Block history. |
| | `hydrate --verify-all` | Reconstructs state AND cryptographically verifies every transaction signature. |

> **Note**: If running manually, `ADRIA_SERVER` env var can be set to target a specific IP (default `127.0.0.1`).

## Managing the Environment

### Stopping & Resetting
To stop all running nodes and clean up data:

**1. Docker Cluster:**
```bash
# Stop containers and remove data volumes
make clean-docker
# Or manually: docker-compose down -v
```

**2. Local Processes:**
```bash
# Kill running adria_server processes
make kill
```

**3. Full Reset (Nuclear Option):**
```bash
# Kills local processes, removes local data, and nukes Docker cluster
make reset-all
```

## License

Open Source.
