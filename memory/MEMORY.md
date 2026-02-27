# Adria Ledger — Session Memory

## Project Overview
Zig blockchain framework (APL) with Ed25519 MSP, permissioned identity, Bitcask state, solo/raft consensus.

## Key File Locations
- `core-sdk/crypto/key.zig` — CertificateV2/V3, MSP, KeyPair
- `core-sdk/common/types.zig` — Transaction, BlockHeader, Block structs; SUPPORTED_PROTOCOL_VERSION
- `core-sdk/cli.zig` — All CLI commands including cert issue/revoke/inspect/audit
- `core-sdk/main.zig` — Adria struct, CertRateTracker, validateTransaction
- `core-sdk/execution/` — db.zig (Bitcask), chaincode.zig, acl.zig, verifier.zig
- `plan.md` — Phase roadmap; current protocol is v2 (u64 network_id + CertificateV2 + CRL)

## Certificate Format
- **V2** (153 bytes): version(1)+serial(8)+subject_pubkey(32)+issuer_pubkey(32)+issued_at(8)+expires_at(8)+signature(64)
- **V3** (188 bytes): V2 layout + flags(2)+role(1)+org(32) inserted before signature; CERT_V3_SIZE=188
- Version byte is byte 0; serial is always bytes 1-8 (LE u64) — version-agnostic revoke works
- V3 signed data (92 bytes): version||serial||subject_pubkey||issued_at||expires_at||flags||role||org

## Protocol Version
- SUPPORTED_PROTOCOL_VERSION = 2 (types.zig). No bump needed for V3 certs — they're off-chain .crt files.
- Transaction struct does NOT carry cert metadata fields beyond the existing V2 fields.

## User Preferences
- Does not want multiple Root CA quorum implemented yet (needs more thought)
- Keep changes minimal and focused — no over-engineering
