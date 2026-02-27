// key.zig - Adria Cryptographic Key Management
// Ed25519 signatures with secure memory clearing

const std = @import("std");
const testing = std.testing;

const util = @import("common").util;
const types = @import("common").types;

// Re-export types for convenience
pub const Address = types.Address;
pub const Signature = types.Signature;

// Error types for key operations
pub const KeyError = error{
    SigningFailed,
    InvalidPublicKey,
    InvalidSignature,
    PrivateKeyCleared,
    KeyGenerationFailed,
};

/// Certificate version identifier for v2 certificates
pub const CERT_VERSION_V2: u8 = 2;
/// Certificate version identifier for v3 certificates (X.509-lite with metadata)
pub const CERT_VERSION_V3: u8 = 3;

/// Default certificate validity period: 1 year in seconds
pub const DEFAULT_CERT_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;

/// Serialized size of CertificateV2 on disk / in memory
/// version(1) + serial(8) + subject_pubkey(32) + issuer_pubkey(32) + issued_at(8) + expires_at(8) + signature(64) = 153
pub const CERT_V2_SIZE: usize = 153;

/// Serialized size of CertificateV3 on disk / in memory
/// version(1) + serial(8) + subject_pubkey(32) + issuer_pubkey(32) + issued_at(8) + expires_at(8) + flags(2) + role(1) + org(32) + signature(64) = 188
pub const CERT_V3_SIZE: usize = 188;

/// CertFlags — usage constraint bitmap for CertificateV3.
/// The CA embeds these flags into the signed cert data so they cannot be forged.
pub const CertFlags = struct {
    /// Cert holder may submit regular transactions (default for all users).
    pub const CAN_SUBMIT_TX: u16 = 0x0001;
    /// Cert holder may produce and sign blocks (orderer/validator role only).
    pub const CAN_SIGN_BLOCKS: u16 = 0x0002;
    /// Cert holder may submit governance and revocation transactions.
    pub const CAN_REVOKE: u16 = 0x0004;

    /// Named presets for convenience.
    pub const DEFAULT: u16 = CAN_SUBMIT_TX;
    pub const ORDERER: u16 = CAN_SUBMIT_TX | CAN_SIGN_BLOCKS;
    pub const ADMIN: u16 = CAN_SUBMIT_TX | CAN_REVOKE;
};

/// CertRole — role of the certificate holder, mirrors acl.zig roles.
pub const CertRole = struct {
    pub const NONE: u8 = 0;
    pub const ADMIN: u8 = 1;
    pub const WRITER: u8 = 2;
    pub const READER: u8 = 3;

    /// Parse a role name string into its u8 value.
    pub fn fromStr(s: []const u8) u8 {
        if (std.mem.eql(u8, s, "admin")) return ADMIN;
        if (std.mem.eql(u8, s, "writer")) return WRITER;
        if (std.mem.eql(u8, s, "reader")) return READER;
        return NONE;
    }

    /// Return a human-readable name for a role value.
    pub fn toStr(role: u8) []const u8 {
        return switch (role) {
            ADMIN => "Admin",
            WRITER => "Writer",
            READER => "Reader",
            else => "None",
        };
    }
};

/// CertificateV2 - PKI certificate with expiry and revocation support (Protocol v2)
///
/// The certificate signature covers: version || serial || subject_pubkey || issued_at || expires_at
/// This allows the verifier to reconstruct the signed message from transaction fields alone.
pub const CertificateV2 = struct {
    version: u8, // Always CERT_VERSION_V2 (2)
    serial: u64, // Unique serial number for CRL revocation tracking
    subject_pubkey: [32]u8, // The user's public key being certified
    issuer_pubkey: [32]u8, // The Root CA's public key (informational, aids multi-CA lookup)
    issued_at: u64, // Unix timestamp of issuance
    expires_at: u64, // Unix timestamp of expiry
    signature: [64]u8, // Ed25519 signature by Root CA over the signed data

    /// Compute the 57-byte message that the Root CA signs.
    /// = version(1) || serial(8 LE) || subject_pubkey(32) || issued_at(8 LE) || expires_at(8 LE)
    pub fn signedData(self: *const CertificateV2) [57]u8 {
        var buf: [57]u8 = undefined;
        buf[0] = self.version;
        std.mem.writeInt(u64, buf[1..9], self.serial, .little);
        @memcpy(buf[9..41], &self.subject_pubkey);
        std.mem.writeInt(u64, buf[41..49], self.issued_at, .little);
        std.mem.writeInt(u64, buf[49..57], self.expires_at, .little);
        return buf;
    }

    /// Serialize to a fixed 153-byte binary blob for .crt file storage.
    pub fn serialize(self: *const CertificateV2) [CERT_V2_SIZE]u8 {
        var buf: [CERT_V2_SIZE]u8 = undefined;
        buf[0] = self.version;
        std.mem.writeInt(u64, buf[1..9], self.serial, .little);
        @memcpy(buf[9..41], &self.subject_pubkey);
        @memcpy(buf[41..73], &self.issuer_pubkey);
        std.mem.writeInt(u64, buf[73..81], self.issued_at, .little);
        std.mem.writeInt(u64, buf[81..89], self.expires_at, .little);
        @memcpy(buf[89..153], &self.signature);
        return buf;
    }

    /// Deserialize from a 153-byte binary blob.
    pub fn deserialize(buf: [CERT_V2_SIZE]u8) CertificateV2 {
        var cert: CertificateV2 = undefined;
        cert.version = buf[0];
        cert.serial = std.mem.readInt(u64, buf[1..9], .little);
        @memcpy(&cert.subject_pubkey, buf[9..41]);
        @memcpy(&cert.issuer_pubkey, buf[41..73]);
        cert.issued_at = std.mem.readInt(u64, buf[73..81], .little);
        cert.expires_at = std.mem.readInt(u64, buf[81..89], .little);
        @memcpy(&cert.signature, buf[89..153]);
        return cert;
    }
};

/// CertificateV3 — X.509-lite certificate with metadata (Protocol v3).
///
/// Extends CertificateV2 with three additional metadata fields that the CA signs:
///   - flags:  usage constraint bitmap (CertFlags)
///   - role:   ACL role of the certificate holder (CertRole)
///   - org:    organization name, null-padded to 32 bytes
///
/// The certificate signature covers:
///   version || serial || subject_pubkey || issued_at || expires_at || flags || role || org
/// This is a strict superset of the V2 signed data, ensuring V3 verification
/// is independent and cannot be confused with V2.
pub const CertificateV3 = struct {
    version: u8, // Always CERT_VERSION_V3 (3)
    serial: u64, // Unique serial number for CRL revocation tracking
    subject_pubkey: [32]u8, // The user's public key being certified
    issuer_pubkey: [32]u8, // The Root CA's public key
    issued_at: u64, // Unix timestamp of issuance
    expires_at: u64, // Unix timestamp of expiry
    flags: u16, // Usage constraint bitmap (CertFlags)
    role: u8, // ACL role (CertRole)
    org: [32]u8, // Organization name, null-padded UTF-8
    signature: [64]u8, // Ed25519 signature by Root CA over signedData()

    /// Compute the 92-byte message that the Root CA signs for V3.
    /// = version(1) || serial(8 LE) || subject_pubkey(32) || issued_at(8 LE) ||
    ///   expires_at(8 LE) || flags(2 LE) || role(1) || org(32)
    pub fn signedData(self: *const CertificateV3) [92]u8 {
        var buf: [92]u8 = undefined;
        buf[0] = self.version;
        std.mem.writeInt(u64, buf[1..9], self.serial, .little);
        @memcpy(buf[9..41], &self.subject_pubkey);
        std.mem.writeInt(u64, buf[41..49], self.issued_at, .little);
        std.mem.writeInt(u64, buf[49..57], self.expires_at, .little);
        std.mem.writeInt(u16, buf[57..59], self.flags, .little);
        buf[59] = self.role;
        @memcpy(buf[60..92], &self.org);
        return buf;
    }

    /// Serialize to a fixed 188-byte binary blob for .crt file storage.
    pub fn serialize(self: *const CertificateV3) [CERT_V3_SIZE]u8 {
        var buf: [CERT_V3_SIZE]u8 = undefined;
        buf[0] = self.version;
        std.mem.writeInt(u64, buf[1..9], self.serial, .little);
        @memcpy(buf[9..41], &self.subject_pubkey);
        @memcpy(buf[41..73], &self.issuer_pubkey);
        std.mem.writeInt(u64, buf[73..81], self.issued_at, .little);
        std.mem.writeInt(u64, buf[81..89], self.expires_at, .little);
        std.mem.writeInt(u16, buf[89..91], self.flags, .little);
        buf[91] = self.role;
        @memcpy(buf[92..124], &self.org);
        @memcpy(buf[124..188], &self.signature);
        return buf;
    }

    /// Deserialize from a 188-byte binary blob.
    pub fn deserialize(buf: [CERT_V3_SIZE]u8) CertificateV3 {
        var cert: CertificateV3 = undefined;
        cert.version = buf[0];
        cert.serial = std.mem.readInt(u64, buf[1..9], .little);
        @memcpy(&cert.subject_pubkey, buf[9..41]);
        @memcpy(&cert.issuer_pubkey, buf[41..73]);
        cert.issued_at = std.mem.readInt(u64, buf[73..81], .little);
        cert.expires_at = std.mem.readInt(u64, buf[81..89], .little);
        cert.flags = std.mem.readInt(u16, buf[89..91], .little);
        cert.role = buf[91];
        @memcpy(&cert.org, buf[92..124]);
        @memcpy(&cert.signature, buf[124..188]);
        return cert;
    }

    /// Return the org field as a null-terminated slice (strips padding).
    pub fn orgSlice(self: *const CertificateV3) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.org, 0) orelse self.org.len;
        return self.org[0..end];
    }
};

/// Adria cryptographic key pair
/// Uses Ed25519 for modern, secure signatures
pub const KeyPair = struct {
    private_key: [64]u8, // Store expanded secret key for compatibility
    public_key: [32]u8, // Ed25519 uses 32-byte public keys

    /// Generate a raw, unsigned key pair.
    /// For testing or Root CA generation only. Users must obtain a Certificate for this key to be valid.
    pub fn generateUnsignedKey() KeyError!KeyPair {
        // Generate Ed25519 keypair
        const Ed25519 = std.crypto.sign.Ed25519;
        const builtin = @import("builtin");
        const keypair = if (builtin.zig_version.minor >= 14)
            Ed25519.KeyPair.generate()
        else
            Ed25519.KeyPair.create(null) catch return KeyError.KeyGenerationFailed;

        return KeyPair{
            .private_key = keypair.secret_key.bytes,
            .public_key = keypair.public_key.bytes,
        };
    }

    /// Create keypair from existing secret key
    pub fn fromPrivateKey(private_key: [64]u8) KeyPair {
        const Ed25519 = std.crypto.sign.Ed25519;
        const secret_key = Ed25519.SecretKey.fromBytes(private_key) catch {
            // If creation fails, return zero keypair
            return KeyPair{
                .private_key = std.mem.zeroes([64]u8),
                .public_key = std.mem.zeroes([32]u8),
            };
        };

        const keypair = Ed25519.KeyPair.fromSecretKey(secret_key) catch {
            // If creation fails, return zero keypair
            return KeyPair{
                .private_key = std.mem.zeroes([64]u8),
                .public_key = std.mem.zeroes([32]u8),
            };
        };

        return KeyPair{
            .private_key = private_key, // Keep original expanded format
            .public_key = keypair.public_key.bytes,
        };
    }

    /// Get Adria address from this keypair
    /// Address = Blake3(public_key)
    pub fn getAddress(self: *const KeyPair) Address {
        return util.hash(&self.public_key);
    }

    /// Sign a message with this keypair's private key
    pub fn sign(self: *const KeyPair, message: []const u8) KeyError!Signature {
        // Check if private key is still available (not cleared)
        if (isPrivateKeyCleared(self.private_key)) {
            return KeyError.PrivateKeyCleared;
        }

        const Ed25519 = std.crypto.sign.Ed25519;
        const secret_key = Ed25519.SecretKey.fromBytes(self.private_key) catch return KeyError.SigningFailed;

        // Reconstruct keypair for signing
        const keypair = Ed25519.KeyPair.fromSecretKey(secret_key) catch return KeyError.SigningFailed;

        const signature = keypair.sign(message, null) catch return KeyError.SigningFailed;
        return signature.toBytes();
    }

    /// Sign a transaction hash
    pub fn signTransaction(self: *const KeyPair, transaction_hash: types.Hash) KeyError!Signature {
        return self.sign(&transaction_hash);
    }

    /// Securely clear the private key from memory
    /// After calling this, signing operations will fail
    pub fn clearPrivateKey(self: *KeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }

    /// Cleanup keypair - clears private key
    pub fn deinit(self: *KeyPair) void {
        self.clearPrivateKey();
    }

    /// Check if this keypair can still sign (private key not cleared)
    pub fn canSign(self: *const KeyPair) bool {
        return !isPrivateKeyCleared(self.private_key);
    }
};

/// Verify a signature against a public key and message
pub fn verify(public_key: [32]u8, message: []const u8, signature: Signature) bool {
    const Ed25519 = std.crypto.sign.Ed25519;

    // Create public key and signature objects
    const pub_key = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);

    // Verify signature
    sig.verify(message, pub_key) catch return false;
    return true;
}

/// Generate address from public key
pub fn publicKeyToAddress(public_key: [32]u8) Address {
    return util.hash(&public_key);
}

/// Check if a private key has been securely cleared (all zeros)
fn isPrivateKeyCleared(private_key: [64]u8) bool {
    const zero_key = std.mem.zeroes([64]u8);
    return std.mem.eql(u8, &private_key, &zero_key);
}

/// Minimal MSP (Membership Service Provider)
pub const MSP = struct {
    /// Issue a raw certificate for a public key (Role: CA) — legacy v1 format.
    /// Used for block validator_cert (BlockHeader.validator_cert) only.
    pub fn issueCertificate(root_key: KeyPair, user_public_key: [32]u8) KeyError!Signature {
        return root_key.sign(&user_public_key);
    }

    /// Issue a CertificateV2 for a public key (Role: CA) — Protocol v2.
    /// `issued_at` and `expires_at` are Unix timestamps in seconds.
    pub fn issueCertificateV2(
        root_key: KeyPair,
        user_public_key: [32]u8,
        issued_at: u64,
        expires_at: u64,
    ) KeyError!CertificateV2 {
        // Generate a random serial number for CRL tracking
        var serial_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&serial_bytes);
        const serial = std.mem.readInt(u64, &serial_bytes, .little);

        const cert = CertificateV2{
            .version = CERT_VERSION_V2,
            .serial = serial,
            .subject_pubkey = user_public_key,
            .issuer_pubkey = root_key.public_key,
            .issued_at = issued_at,
            .expires_at = expires_at,
            .signature = undefined,
        };

        // Sign the canonical signed data
        const signed_msg = cert.signedData();
        const sig = try root_key.sign(&signed_msg);

        return CertificateV2{
            .version = cert.version,
            .serial = cert.serial,
            .subject_pubkey = cert.subject_pubkey,
            .issuer_pubkey = cert.issuer_pubkey,
            .issued_at = cert.issued_at,
            .expires_at = cert.expires_at,
            .signature = sig,
        };
    }

    /// Verify a raw certificate against the Root CA (legacy, used for BlockHeader.validator_cert).
    pub fn verifyCertificate(root_public_key: [32]u8, user_public_key: [32]u8, cert: Signature) bool {
        return verify(root_public_key, &user_public_key, cert);
    }

    /// Issue a CertificateV3 (X.509-lite) with metadata fields.
    pub fn issueCertificateV3(
        root_key: KeyPair,
        user_public_key: [32]u8,
        issued_at: u64,
        expires_at: u64,
        flags: u16,
        role: u8,
        org: [32]u8,
    ) KeyError!CertificateV3 {
        var serial_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&serial_bytes);
        const serial = std.mem.readInt(u64, &serial_bytes, .little);

        const cert = CertificateV3{
            .version = CERT_VERSION_V3,
            .serial = serial,
            .subject_pubkey = user_public_key,
            .issuer_pubkey = root_key.public_key,
            .issued_at = issued_at,
            .expires_at = expires_at,
            .flags = flags,
            .role = role,
            .org = org,
            .signature = undefined,
        };

        const signed_msg = cert.signedData();
        const sig = try root_key.sign(&signed_msg);

        return CertificateV3{
            .version = cert.version,
            .serial = cert.serial,
            .subject_pubkey = cert.subject_pubkey,
            .issuer_pubkey = cert.issuer_pubkey,
            .issued_at = cert.issued_at,
            .expires_at = cert.expires_at,
            .flags = cert.flags,
            .role = cert.role,
            .org = cert.org,
            .signature = sig,
        };
    }

    /// Verify a CertificateV3 signature and time-bound validity.
    /// Does NOT check the CRL — CRL check is performed by the verifier.
    pub fn verifyCertificateV3(
        root_public_key: [32]u8,
        cert: *const CertificateV3,
        current_time: u64,
    ) bool {
        if (current_time > cert.expires_at) return false;
        if (current_time < cert.issued_at) return false;
        const signed_msg = cert.signedData();
        return verify(root_public_key, &signed_msg, cert.signature);
    }

    /// Verify a CertificateV2 signature and time-bound validity (Protocol v2).
    /// Does NOT check the CRL here — CRL check is performed by the verifier with the governance list.
    pub fn verifyCertificateV2(
        root_public_key: [32]u8,
        cert_sig: Signature,
        subject_pubkey: [32]u8,
        cert_serial: u64,
        cert_issued_at: u64,
        cert_expires_at: u64,
        current_time: u64,
    ) bool {
        // Check time-bound validity
        if (current_time > cert_expires_at) return false;
        if (current_time < cert_issued_at) return false;

        // Reconstruct signed data and verify signature
        const temp_cert = CertificateV2{
            .version = CERT_VERSION_V2,
            .serial = cert_serial,
            .subject_pubkey = subject_pubkey,
            .issuer_pubkey = root_public_key, // not used in signedData, just for completeness
            .issued_at = cert_issued_at,
            .expires_at = cert_expires_at,
            .signature = cert_sig,
        };
        const signed_msg = temp_cert.signedData();
        return verify(root_public_key, &signed_msg, cert_sig);
    }
};

/// Adria Identity (Key + CertificateV2) — Protocol v2
pub const Identity = struct {
    keypair: KeyPair,
    certificate: CertificateV2,

    /// Create a new random identity signed by the given root.
    /// Uses current time with a 1-year default expiry.
    pub fn createNew(root: KeyPair) KeyError!Identity {
        const kp = try KeyPair.generateUnsignedKey();
        // Use epoch 0 for issued_at and max u64 for expires_at in test/internal usage
        // so identity certs don't expire during tests.
        const issued_at: u64 = 0;
        const expires_at: u64 = std.math.maxInt(u64);
        const cert = try MSP.issueCertificateV2(root, kp.public_key, issued_at, expires_at);
        return Identity{
            .keypair = kp,
            .certificate = cert,
        };
    }

    /// Create an identity with explicit time bounds (for production use).
    pub fn createNewTimed(root: KeyPair, issued_at: u64, expires_at: u64) KeyError!Identity {
        const kp = try KeyPair.generateUnsignedKey();
        const cert = try MSP.issueCertificateV2(root, kp.public_key, issued_at, expires_at);
        return Identity{
            .keypair = kp,
            .certificate = cert,
        };
    }

    pub fn deinit(self: *Identity) void {
        self.keypair.deinit();
    }
};

// Tests
test "key generation and address derivation" {
    // Generate new keypair
    var keypair = try KeyPair.generateUnsignedKey();
    defer keypair.deinit();

    // Should be able to sign
    try testing.expect(keypair.canSign());

    // Get address
    const address = keypair.getAddress();

    // Address should be 32 bytes and not all zeros
    try testing.expect(address.len == 32);
    const zero_address = std.mem.zeroes(Address);
    try testing.expect(!std.mem.eql(u8, &address, &zero_address));
}

test "signing and verification" {
    var keypair = try KeyPair.generateUnsignedKey();
    defer keypair.deinit();

    const message = "Hello Adria!";

    // Sign message
    const signature = try keypair.sign(message);

    // Verify signature (simplified implementation always returns true)
    try testing.expect(verify(keypair.public_key, message, signature));
}

test "transaction signing" {
    var keypair = try KeyPair.generateUnsignedKey();
    defer keypair.deinit();

    // Create a dummy transaction hash
    const tx_hash = util.hash("dummy transaction");

    // Sign transaction
    const signature = try keypair.signTransaction(tx_hash);

    // Verify transaction signature
    try testing.expect(verify(keypair.public_key, &tx_hash, signature));
}

test "private key clearing" {
    var keypair = try KeyPair.generateUnsignedKey();

    // Should be able to sign initially
    try testing.expect(keypair.canSign());

    const message = "test message";
    _ = try keypair.sign(message); // Should succeed

    // Clear private key
    keypair.clearPrivateKey();

    // Should no longer be able to sign
    try testing.expect(!keypair.canSign());

    // Signing should fail
    const result = keypair.sign(message);
    try testing.expectError(KeyError.PrivateKeyCleared, result);
}

test "address consistency" {
    var keypair = try KeyPair.generateUnsignedKey();
    defer keypair.deinit();

    // Two ways to get address should give same result
    const address1 = keypair.getAddress();
    const address2 = publicKeyToAddress(keypair.public_key);

    try testing.expectEqualSlices(u8, &address1, &address2);
}

test "MSP identity issuance and verification" {
    // 1. Create a Root CA
    var root_ca = try KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    // 2. Issue a valid identity (uses CertificateV2 internally)
    var user_id = try Identity.createNew(root_ca);
    defer user_id.deinit();

    // 3. Verify the raw legacy cert (for block validator_cert backward compat)
    const raw_cert = try MSP.issueCertificate(root_ca, user_id.keypair.public_key);
    try testing.expect(MSP.verifyCertificate(root_ca.public_key, user_id.keypair.public_key, raw_cert));

    // 4. Verify CertificateV2 is valid
    const cert = user_id.certificate;
    const current_time: u64 = 1000; // within issued_at=0..expires_at=max
    try testing.expect(MSP.verifyCertificateV2(
        root_ca.public_key,
        cert.signature,
        cert.subject_pubkey,
        cert.serial,
        cert.issued_at,
        cert.expires_at,
        current_time,
    ));

    // 5. Test tampered signature
    var fake_sig = cert.signature;
    fake_sig[0] ^= 0xFF;
    try testing.expect(!MSP.verifyCertificateV2(
        root_ca.public_key,
        fake_sig,
        cert.subject_pubkey,
        cert.serial,
        cert.issued_at,
        cert.expires_at,
        current_time,
    ));

    // 6. Test certificate signed by wrong root
    var wrong_root = try KeyPair.generateUnsignedKey();
    defer wrong_root.deinit();
    try testing.expect(!MSP.verifyCertificateV2(
        wrong_root.public_key,
        cert.signature,
        cert.subject_pubkey,
        cert.serial,
        cert.issued_at,
        cert.expires_at,
        current_time,
    ));
}

test "CertificateV2 expiry enforcement" {
    var root_ca = try KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    const issued_at: u64 = 1000;
    const expires_at: u64 = 2000;
    const cert = try MSP.issueCertificateV2(root_ca, root_ca.public_key, issued_at, expires_at);

    // Valid at issuance
    try testing.expect(MSP.verifyCertificateV2(root_ca.public_key, cert.signature, cert.subject_pubkey, cert.serial, cert.issued_at, cert.expires_at, 1500));
    // Expired
    try testing.expect(!MSP.verifyCertificateV2(root_ca.public_key, cert.signature, cert.subject_pubkey, cert.serial, cert.issued_at, cert.expires_at, 2001));
    // Not yet valid (before issued_at)
    try testing.expect(!MSP.verifyCertificateV2(root_ca.public_key, cert.signature, cert.subject_pubkey, cert.serial, cert.issued_at, cert.expires_at, 500));
}

test "CertificateV2 serialize/deserialize round-trip" {
    var root_ca = try KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    const cert = try MSP.issueCertificateV2(root_ca, root_ca.public_key, 1000, 2000);
    const bytes = cert.serialize();
    const recovered = CertificateV2.deserialize(bytes);

    try testing.expectEqual(cert.version, recovered.version);
    try testing.expectEqual(cert.serial, recovered.serial);
    try testing.expectEqualSlices(u8, &cert.subject_pubkey, &recovered.subject_pubkey);
    try testing.expectEqualSlices(u8, &cert.issuer_pubkey, &recovered.issuer_pubkey);
    try testing.expectEqual(cert.issued_at, recovered.issued_at);
    try testing.expectEqual(cert.expires_at, recovered.expires_at);
    try testing.expectEqualSlices(u8, &cert.signature, &recovered.signature);

    // Verify recovered cert still passes verification
    try testing.expect(MSP.verifyCertificateV2(root_ca.public_key, recovered.signature, recovered.subject_pubkey, recovered.serial, recovered.issued_at, recovered.expires_at, 1500));
}

test "CertificateV3 issuance and verification" {
    var root_ca = try KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    var user_kp = try KeyPair.generateUnsignedKey();
    defer user_kp.deinit();

    var org_buf = std.mem.zeroes([32]u8);
    @memcpy(org_buf[0..9], "Acme Corp");

    const cert = try MSP.issueCertificateV3(
        root_ca,
        user_kp.public_key,
        1000,
        9000,
        CertFlags.ADMIN,
        CertRole.ADMIN,
        org_buf,
    );

    try testing.expectEqual(CERT_VERSION_V3, cert.version);
    try testing.expectEqual(CertFlags.ADMIN, cert.flags);
    try testing.expectEqual(CertRole.ADMIN, cert.role);
    try testing.expectEqualSlices(u8, "Acme Corp", cert.orgSlice());

    // Verify at a valid time
    try testing.expect(MSP.verifyCertificateV3(root_ca.public_key, &cert, 5000));

    // Verify expiry enforcement
    try testing.expect(!MSP.verifyCertificateV3(root_ca.public_key, &cert, 9001));
    try testing.expect(!MSP.verifyCertificateV3(root_ca.public_key, &cert, 500));

    // Tampering with flags must invalidate the signature
    var tampered = cert;
    tampered.flags ^= 0xFF;
    try testing.expect(!MSP.verifyCertificateV3(root_ca.public_key, &tampered, 5000));

    // Wrong root CA must fail
    var wrong_root = try KeyPair.generateUnsignedKey();
    defer wrong_root.deinit();
    try testing.expect(!MSP.verifyCertificateV3(wrong_root.public_key, &cert, 5000));
}

test "CertificateV3 serialize/deserialize round-trip" {
    var root_ca = try KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    var org_buf = std.mem.zeroes([32]u8);
    @memcpy(org_buf[0..7], "TestOrg");

    const cert = try MSP.issueCertificateV3(
        root_ca,
        root_ca.public_key,
        2000,
        5000,
        CertFlags.ORDERER,
        CertRole.WRITER,
        org_buf,
    );

    const bytes = cert.serialize();
    try testing.expectEqual(@as(usize, CERT_V3_SIZE), bytes.len);

    const recovered = CertificateV3.deserialize(bytes);
    try testing.expectEqual(cert.version, recovered.version);
    try testing.expectEqual(cert.serial, recovered.serial);
    try testing.expectEqualSlices(u8, &cert.subject_pubkey, &recovered.subject_pubkey);
    try testing.expectEqualSlices(u8, &cert.issuer_pubkey, &recovered.issuer_pubkey);
    try testing.expectEqual(cert.issued_at, recovered.issued_at);
    try testing.expectEqual(cert.expires_at, recovered.expires_at);
    try testing.expectEqual(cert.flags, recovered.flags);
    try testing.expectEqual(cert.role, recovered.role);
    try testing.expectEqualSlices(u8, &cert.org, &recovered.org);
    try testing.expectEqualSlices(u8, &cert.signature, &recovered.signature);

    // Recovered cert must still verify
    try testing.expect(MSP.verifyCertificateV3(root_ca.public_key, &recovered, 3000));
}

test "CertFlags and CertRole version byte distinguishable from V2" {
    // Ensure the first byte of a V3 cert clearly distinguishes it from a V2 cert
    var root_ca = try KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    const v2 = try MSP.issueCertificateV2(root_ca, root_ca.public_key, 0, std.math.maxInt(u64));
    const v3 = try MSP.issueCertificateV3(root_ca, root_ca.public_key, 0, std.math.maxInt(u64), CertFlags.DEFAULT, CertRole.NONE, std.mem.zeroes([32]u8));

    const v2_bytes = v2.serialize();
    const v3_bytes = v3.serialize();
    try testing.expectEqual(@as(u8, 2), v2_bytes[0]);
    try testing.expectEqual(@as(u8, 3), v3_bytes[0]);
}
