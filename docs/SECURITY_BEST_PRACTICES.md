# Security Best Practices for Adria

Adria is designed with security in mind, but operational security depends on how you manage your keys and infrastructure.

## Key Management

### Offline Signing (Cold Storage)
For critical keys (like the Root CA or high-value wallets), I recommend **Offline Signing**.

**Workflow:**
1.  **Generate Keys Offline**: Create your wallet on an air-gapped machine (never connected to the internet) using `apl wallet create <name>`.
2.  **Prepare Transaction Online**: On your online node, determine the transaction payload, the target network's `network_id`, and the sender's current `nonce` (via `apl nonce <address>`).
3.  **Transfer to Cold Storage**: Move the unsigned metadata (payload, nonce, network ID) to your air-gapped machine.
4.  **Sign Offline**: Run `apl tx sign <payload> <nonce> <network_id> [wallet]` on the air-gapped machine. This generates a raw, signed transaction string.
5.  **Broadcast Online**: Move the signed string back to the online node and submit it using `apl tx broadcast <raw_tx>`.

> **Note**: You can verify this flow works locally by running the automated test: `make test-offline`

### Identity & Certificates (MSP)
Adria relies on a permissioned Membership Service Provider (MSP) model. All participants must be explicitly authorized by a trusted Certificate Authority (CA) before they can interact with the network.

- **Root CA Security**: Ensure you securely generate your Root CA wallet (`apl wallet create root_ca`) offline. The public key of this wallet must be distributed to all nodes via the `consensus.seed_root_ca` field in `adria-config.json`.
- **Issuing Certificates**: Only issue certificates to trusted participants using `apl cert issue <ca_wallet> <target_wallet>`. This generates an off-chain `.crt` file that validates their identity on the network.
- **Test Suite**: The full suite of identity commands is tested automatically via `make test-cli`.

### Memory Hygiene
- Adria's `apl` CLI and `adria_server` are designed to zero out private keys in memory immediately after use (`memset`).
- Avoid running other untrusted processes on the same machine as your validator node to prevent memory scraping.

## Network Security

### Network Identity
- **Network ID**: Every Adria network has a unique `network_id` in `adria-config.json`.
- **Replay Protection**: This ID is included in every transaction signature. This prevents a transaction signed for a TestNet from being maliciously replayed on a MainNet.
- **Dynamic Discovery**: The `apl` CLI automatically discovers the `network_id` directly from the server's `STATUS` endpoint to prevent human error when formatting transactions online.
- **Recommendation**: Ensure `adria-config.json` has the correct `network_id` for the environment you are validating.

### Firewall Configuration
- **Bind Address**: By default, Adria binds to `127.0.0.1` (localhost). 
    - **To Expose**: You must explicitly configure `bind_address` in `adria-config.json` to allow external connections.
- **P2P Port (Default 10801)**: This port handles the peer-to-peer gossip protocol (syncing blocks/txs).
    - **Global Access**: As a permissioned ledger, this port should **NOT** be exposed to the public internet.
    - **Private Network**: Restrict access to your private subnet (e.g., `10.x.x.x`) or VPN interface.
    - **Firewall**: Allow incoming TCP and UDP traffic on this port *only* from other known, authorized peer nodes.
- **API Port (Default 10802)**: This port is used by your applications (CLI, Web Backend) to submit transactions and query state.
    - **No Authentication**: The node creates a raw TCP socket that accepts commands from *anyone* who can connect. It does verify transaction signatures, but the *connection itself* is currently unauthenticated.
    - **Recommendation**: Keep this bound to `127.0.0.1` (default) if your application is on the same machine.
    - **Remote Access**: If your application is on a different server within your private cluster, use a VPN/SSH Tunnel. Do **NOT** expose this port to the public internet.

### DOS Protection
- Adria has built-in limits for connection counts and request sizes.
- I recommend placing a standard DDoS mitigation layer (i.e. Cloudflare, AWS Shield) in front of your public-facing nodes if you are a validator.

## Data Integrity
- Adria uses an Append-Only Log. Backups are as simple as copying the `blocks/` directory.
- `state/` directory can always be reconstructed from `blocks/` using `apl hydrate`. I recommend backing up `blocks/` frequently.
