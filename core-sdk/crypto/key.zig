// key.zig - Adria Cryptographic Key Management
// Ed25519 signatures with secure memory clearing

const std = @import("std");
const testing = std.testing;

const util = @import("../common/util.zig");
const types = @import("../common/types.zig");

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

/// Adria cryptographic key pair
/// Uses Ed25519 for modern, secure signatures
pub const KeyPair = struct {
    private_key: [64]u8, // Store expanded secret key for compatibility
    public_key: [32]u8, // Ed25519 uses 32-byte public keys

    /// Generate a raw, unsigned key pair.
    /// ⚠️  For testing or Root CA generation only. Users must obtain a Certificate for this key to be valid.
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

/// 🛡️ Minimal MSP (Membership Service Provider)
/// In a real system, this would use X.509 certs.
/// For this PoC, a "Certificate" is just the User's Public Key signed by the Root CA.
pub const MSP = struct {
    /// Issue a certificate for a public key (Role: CA)
    pub fn issueCertificate(root_key: KeyPair, user_public_key: [32]u8) KeyError!Signature {
        // Sign the user's public key with the root private key
        return root_key.sign(&user_public_key);
    }

    /// Verify a user's certificate against the Root CA (Role: Validator)
    pub fn verifyCertificate(root_public_key: [32]u8, user_public_key: [32]u8, cert: Signature) bool {
        // Verify that 'cert' is a valid signature of 'user_public_key' by 'root_public_key'
        return verify(root_public_key, &user_public_key, cert);
    }
};

/// Adria Identity (Key + Certificate)
pub const Identity = struct {
    keypair: KeyPair,
    certificate: Signature,

    /// Create a new random identity signed by the given root (for testing/setup)
    pub fn createNew(root: KeyPair) KeyError!Identity {
        const kp = try KeyPair.generateUnsignedKey();
        const cert = try MSP.issueCertificate(root, kp.public_key);
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

    // 2. Issue a valid identity
    var user_id = try Identity.createNew(root_ca);
    defer user_id.deinit();

    // 3. Verify the certificate is valid for this user and root
    try testing.expect(MSP.verifyCertificate(root_ca.public_key, user_id.keypair.public_key, user_id.certificate));

    // 4. Test invalid certificate (tampered signature)
    var fake_cert = user_id.certificate;
    fake_cert[0] ^= 0xFF; // Flip bits
    try testing.expect(!MSP.verifyCertificate(root_ca.public_key, user_id.keypair.public_key, fake_cert));

    // 5. Test certificate signed by wrong root
    var wrong_root = try KeyPair.generateUnsignedKey();
    defer wrong_root.deinit();
    try testing.expect(!MSP.verifyCertificate(wrong_root.public_key, user_id.keypair.public_key, user_id.certificate));
}
