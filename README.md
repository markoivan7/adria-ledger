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
*   **Permissioned / MSP**: No anonymous keys. All participants are rigorously authenticated via Ed25519 cryptographic certificates signed by an on-chain Root Certificate Authority (CA).
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
Adria supports **On-Chain Storage** for data, but you should follow the Hybrid Model:

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

3.  **Identity (The Certificate Authority)**:
    *   *How it works*: Adria uses a hybrid approach for identities to keep the ledger lightweight.
    *   **On-Chain Root CA**: The identity of the Root Certificate Authority is baked into the immutable blockchain (Block 0 / Genesis Block) via the `seed_root_ca` configuration. This acts as the ultimate source of truth for who is trusted to authorize users.
    *   **Off-Chain User Certificates**: When a user registers, the Root CA signs their public key locally. This creates an off-chain `.crt` file (a "digital passport"). There is *no on-chain transaction* created for this issuance, preventing chain bloat.
    *   **Transaction Validation**: When a user submits a business transaction, they attach their `.crt` passport. The network nodes verify the passport against the on-chain Root CA before executing the business logic.

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
Adria includes a tool, `apl hydrate`, to rebuild the state from scratch.

*   **Fast Mode (Default)**: Replays blocks to rebuild state, checking hash continuity chains (Trust-On-First-Use). Fast state recovery.
*   **Audit Mode (`--verify-all`)**: Re-verifies **every cryptographic signature** and certificate on every transaction in history. This provides a mathematical guarantee that the current state is the result of valid, authorized transactions.

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

*   `core-sdk/` - The main Zig implementation.
    *   `execution/` - State machine, DB, Chaincode, and ACL.
    *   `consensus/` - Ordering interfaces and implementations (Solo).
    *   `network/` - P2P networking and protocol handlers.
    *   `crypto/` - Cryptographic primitives (Ed25519, BLAKE3, Certificates).
    *   `ingestion/` - Transaction pool and parallel verification workers.
*   `tests/` - Integration, functional, and security tests.

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

#### 4. Run the Full Test Suite
Validate that all tests (Core, CLI, Document, Security) pass:
```bash
make test
```
#### 5. Configuration (`adria-config.json`)

**Key Settings:**
*   `network.bind_address`: Default is `127.0.0.1`.
*   `network.network_id`: Unique identifier for the network instance. Generated randomly by default on first run to prevent cross-network replay attacks. Can be set manually (e.g., 1 for TestNet, 2 for MainNet).
*   `consensus.role`: `orderer` (produces blocks) or `peer` (validates only).

**Example `adria-config.example.json`:**
```json
{
    "network": {
        "p2p_port": 10801,
        "api_port": 10802,
        "discovery": true,
        "bind_address": "127.0.0.1",
        "network_id": 1
    },
    "storage": {
        "data_dir": "apl_data",
        "log_level": "info"
    },
    "consensus": {
        "mode": "solo",
        "role": "peer"
    }
}
```

## Test Suite & Demos

Adria includes several pre-built scenarios to verify functionality.

### 1. General Ledger PoC (Functional Integrity)
**Goal:** Verify the integrity of the ledger and the hybrid storage model.
*   **What it does:** Simulates a client recording data, validates cryptographic anchors, and ensures the World State matches the blockchain history.
*   **Command:**
    ```bash
    make test-core
    ```

### 2. Asset Transfer Demo
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

### 5. CLI Verification Suite
**Goal:** Verify all Command-Line Interface operations.
*   **What it does:** Tests wallet creation, certificate issuance, offline signing, broadcasting, and ledger queries via the `apl` CLI.
*   **Command:**
    ```bash
    make test-cli
    ```

### 6. Offline Signing Verification
**Goal:** Verify that transactions can be signed securely without network access.
*   **What it does:** Creates an offline tester identity, retrieves network ID and nonce, generates a raw offline signature, and broadcasts it for successful inclusion.
*   **Command:**
    ```bash
    make test-offline
    ```

### 7. Governance Unit Tests
**Goal:** Verify protocol governance and access control logic.
*   **What it does:** Runs native Zig unit tests to validate role-based access control, validator signatures, and genesis block configuration.
*   **Command:**
    ```bash
    make test-governance
    ```

### 8. Security Testing (DoS Protection)
**Goal**: Verify the node's resilience against common network attacks.
*   **What it does**: Floods the node with malformed packets, invalid protocol messages, and rapid connection attempts.
*   **Command**:
    ```bash
    make test-security
    ```

### 9. Full Integrated Test Suite
**Goal**: Run all end-to-end regression tests to ensure total system integrity.
*   **What it does**: Automatically executes all the above functional suites.
*   **Command**:
    ```bash
    make test
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

For interactive testing, you can run the server and CLI manually. However, because Adria is a permissioned ledger, you must configure a Root CA first.

**1. Create the Root CA Identity**
```bash
./core-sdk/zig-out/bin/apl wallet create my_root_ca
./core-sdk/zig-out/bin/apl pubkey my_root_ca --raw
```
*Copy the resulting public key hex string and add it to `adria-config.json` under `consensus.seed_root_ca`.*

**2. Start the Server**
```bash
make run
```
*Starts Orderer on localhost (P2P: 10801, API: 10802).*

**3. Run CLI Commands**
Open a new terminal to create your execution wallet and issue it a certificate:
```bash
# Create wallet
./core-sdk/zig-out/bin/apl wallet create mywallet

# Issue a certificate to 'mywallet' signed by the Root CA
./core-sdk/zig-out/bin/apl cert issue my_root_ca mywallet

# Record data to the ledger
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
| | `address [wallet] [--raw]` | Displaying the address (hex) of a specific wallet. |
| **Identity** | `pubkey [wallet] [--raw]` | Displaying the public key (hex) of a specific wallet. |
| | `cert issue <signer_wallet> <target_wallet>` | Generating an identity certificate for a target wallet, signed by a Root CA wallet. |
| | `nonce <address>` | Querying the current nonce for an address. |
| **Transaction** | `tx sign <payload> <nonce> <net_id> [wallet]` | Generating a raw offline signature without connecting to a node. |
| | `tx broadcast <raw_tx>` | Broadcasting a pre-signed transaction payload to the network. |
| **Ledger** | `ledger record <key> <val>` | Submitting a generic data entry to the blockchain. |
| | `ledger query <key>` | Querying the state for a specific key (Proof of Existence). |
| **Documents** | `document store <collection> <id> <file>` | Storing a large document (up to 60KB) on-chain. |
| | `document retrieve <collection> <id>` | Retrieving a stored document from the local state. |
| **Reconstruction**| `hydrate [--verify-all]` | Reconstructs the World State from the Block history. |

> **Note**: Set the `ADRIA_SERVER` environment variable to target a specific IP (default `127.0.0.1`).

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

## Identity, Key Management & Security

Security is critical for a permissioned ledger. Adria provides tools to help you manage your keys and network identities safely.

### Identity & Certificates (MSP)
Unlike permissionless networks where anyone can submit transactions anonymously, Adria relies on a **Root Certificate Authority (CA)** to authorize participants.
*   **Root CA**: The network is initialized with one or more public keys of a Root CA (`consensus.seed_root_ca` in the config).
*   **Certificates**: Before a participant can interact with the network, the Root CA must sign their public key. This signature becomes their off-chain "Certificate" (stored in `apl_data/wallets/<name>.crt`).
*   **Enforcement**: The Orderer and Validators verify the sender's certificate against the Root CA on every transaction. If a participant's public key was not signed by a recognized CA, their transaction is rejected immediately (`Permission Denied`).

#### Modifying the Config for the CA:
1. Create the CA identity: `apl wallet create my_root_ca`
2. Extract the public key: `apl pubkey my_root_ca --raw`
3. Add this hex string to `adria-config.json` under `consensus.seed_root_ca`.
4. Issue operator certificates: `apl cert issue my_root_ca user_wallet`

### Wallet Format (`.wallet`)
Wallets are encrypted JSON files containing your Ed25519 keypair.
*   **Encryption**: Keys are encrypted using **PBKDF2** (4096 iterations) + **XOR**.
*   **Integrity**: Files are protected by a **BLAKE3 checksum** to detect corruption or tampering.
*   **Location**: Default storage is `apl_data/wallets/`.

### Best Practices
1.  **Offline Signing (Cold Storage)**:
    *   For high-value keys (Root CA, Validators), use an air-gapped machine.
    *   Generate keys and sign transactions offline, then broadcast via an online node.

2.  **Memory Hygiene**:
    *   Adria automatically zeros out private keys in memory after use (`secureZero`).
    *   Never run untrusted code on the same machine as your validator node.

3.  **Network Isolation**:
    *   **Bind to Localhost**: By default, Adria binds to `127.0.0.1`. Please ensure you are on a secure network before changing this.
    *   **Firewall**: Whitelist only known peer IPs on port 10801.

## License

Open Source.
