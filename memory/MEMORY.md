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
- SUPPORTED_PROTOCOL_VERSION = 2 (types.zig). Active network protocol is v2: u64 network_id + CertificateV2 + CRL.
- CertificateV3 (flags, role, org) is a key.zig LIBRARY PREVIEW ONLY. Not active at network level.
  - invokeChaincode reads only CERT_V2_SIZE (153 bytes) from .crt files — V3 .crt (188 bytes) silently misreads
  - Transaction struct does NOT carry V3 fields (flags, role, org). Protocol v3 bump required before V3 is usable.
- plan.md "Protocol v3 upgrade" label for cert revocation was incorrect — corrected to Protocol v2.

## Hydrate Tool (apl hydrate)
- `tools/hydrate.zig` — Full audit mode now implemented
  - Fast mode: chain continuity + chaincode replay (genesis governance reconstructed via writeGenesisGovernance)
  - Audit mode (--verify-all): additionally verifies block validator cert, tx CertificateV2, CRL per block
  - Uses block.header.timestamp (not current time) for cert expiry checks — replay-safe
  - Reads seed_root_ca from adria-config.json to init root CAs; updated from governance state after each block
  - writeGenesisGovernance() mirrors createGenesis() — fixes governance replay for cert revocation chains

## User Preferences
- Does not want multiple Root CA quorum implemented yet (needs more thought)
- Keep changes minimal and focused — no over-engineering
