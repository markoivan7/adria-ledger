# Adria Permissioned Ledger v0.1.0

First public release of the Adria Permissioned Ledger (APL) — a lightweight, high-performance blockchain framework written in Zig, designed for enterprise identity and data integrity use cases.

## What's in v0.1.0

### Core Protocol (Protocol v2)
- **u64 Network IDs** — 18 quintillion possible values, eliminating cross-network collision risk
- **CertificateV2** (153 bytes) — Ed25519 certificates with serial number, expiry timestamp, and Root CA signature
- **Certificate Revocation List (CRL)** — on-chain revocation via `apl cert revoke`; revoked serials are rejected at the transaction boundary
- **Certificate Expiry** — time-bounded certificates enforced at block-commit time
- **Transaction Timestamp Validation** — ±5 min future / ±1 hour past tolerance window prevents timestamp manipulation

### Wallet Security
- **Argon2id KDF** (t=3, m=64 MB, p=1) — memory-hard key derivation; each unlock allocates ~64 MB of RAM for ~100–200 ms, making offline brute-force attacks impractical
- **ChaCha20-Poly1305 AEAD** — Provides authenticated encryption with no separate checksum field
- **Interactive password prompt** — wallet creation requires a password (with confirmation), echo disabled
- Wallet file format: 192 bytes (version 2)

### Identity & Security
- **MSP (Membership Service Provider)** — all participants must hold a certificate signed by the on-chain Root CA
- **Three-layer transaction validation**: Network ID → Certificate → Ed25519 Signature
- **Parallel Verification** — Ed25519 verification runs in a thread pool
- **DoS Protection** — connection limits, read timeouts, and malformed-packet resistance
- **Certificate Usage Monitoring** — `[CERT_USAGE]` log lines + `[CERT_ALERT]` on burst rate (>100 tx/min per serial)
- **CertificateV3 preview** — extended metadata (flags, role, org) implemented in `crypto/key.zig`

### Storage & Execution
- **Bitcask Storage Engine** — pure Zig, dependency-free append-only log with in-memory index
- **Event Sourcing** — the blockchain is the Write-Ahead Log (WAL); world state is a reconstructible view
- **`apl hydrate`** — fast-mode and full audit-mode (`--verify-all`) state reconstruction
- **DocumentStore** — up to 64 KB JSON documents on-chain
- **DatasetStore** — client-side materialization of massive JSON arrays (100K+ rows) via chunked append/commit

### CLI & Tooling
- **`apl engine backup`** — safety snapshot before a same-protocol binary swap
- **`apl engine checkpoint`** — automated migration tool for protocol version bumps
- **`apl cert audit <address>`** — offline WAL scan showing full certificate usage history
- **`apl cert inspect <wallet>`** — display V2/V3 certificate metadata
- **`apl tx sign` / `apl tx broadcast`** — air-gapped offline signing workflow
- **`apl dataset diff`** — O(1) structural diff between dataset snapshots
- **`apl version`** / **`apl protocol`** — binary and protocol version introspection

## Binaries

| File | Platform |
|---|---|
| `adria-v0.1.0-macos-arm64.tar.gz` | macOS Apple Silicon (ARM64) |
| `adria-v0.1.0-linux-x86_64.tar.gz` | Linux x86_64 (static musl, no dependencies) |

Each archive contains: `adria_server`, `apl`, `adria-config.example.json`, `README.md`, `LICENSE`, `QUICK_START.txt`.

## Requirements

- No runtime dependencies (Zig stdlib is statically linked)
- macOS 12+ / Linux kernel 4.x+
- Zig **0.14.1** required only if building from source

## Building from Source

```bash
git clone https://github.com/markoivan7/adria-ledger.git
cd adria-ledger
make build
```

## Quick Start

See `QUICK_START.txt` inside the archive, or the [README](README.md) for the full CLI reference.

## License

Apache 2.0
