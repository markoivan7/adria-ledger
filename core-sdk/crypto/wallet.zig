// wallet.zig - Adria Minimal Wallet

const std = @import("std");
const types = @import("common").types;
const key = @import("key.zig");
const util = @import("common").util;

/// Adria wallet errors - simple and clear
pub const WalletError = error{
    NoWalletLoaded,
    WalletFileNotFound,
    InvalidPassword,
    CorruptedWallet,
    InvalidWalletFile,
    OutdatedWalletFormat,
};

// Argon2id parameters (OWASP 2023 interactive recommendation)
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEM_COST_KB: u32 = 65536; // 64 MB
const ARGON2_PARALLELISM: u24 = 1;

const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const KEY_LEN = ChaCha.key_length; // 32
const NONCE_LEN = ChaCha.nonce_length; // 12
const TAG_LEN = ChaCha.tag_length; // 16
const PRIVKEY_LEN = 64;
const CIPHERTEXT_LEN = PRIVKEY_LEN + TAG_LEN; // 80

/// Adria wallet file format v2:
///   version               u32     4 bytes   (= 2)
///   salt                  [32]u8  32 bytes  Argon2id salt
///   nonce                 [12]u8  12 bytes  ChaCha20-Poly1305 nonce
///   encrypted_private_key [80]u8  80 bytes  64 B ciphertext + 16 B Poly1305 tag
///   public_key            [32]u8  32 bytes
///   address               [32]u8  32 bytes
///   Total: 192 bytes
///
/// The Poly1305 tag authenticates the ciphertext + public_key (as AEAD additional data),
/// making a separate checksum field unnecessary.
pub const WalletFile = struct {
    version: u32,
    salt: [32]u8,
    nonce: [NONCE_LEN]u8,
    encrypted_private_key: [CIPHERTEXT_LEN]u8,
    public_key: [32]u8,
    address: types.Address,

    /// Create wallet file from private key (64-byte Ed25519 secret key)
    pub fn fromPrivateKey(private_key_64: [64]u8, password: []const u8, allocator: std.mem.Allocator) !WalletFile {
        var salt: [32]u8 = undefined;
        std.crypto.random.bytes(&salt);

        var nonce: [NONCE_LEN]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        const adria_keypair = key.KeyPair.fromPrivateKey(private_key_64);
        const address = deriveAddress(adria_keypair.public_key);

        var encrypted_key: [CIPHERTEXT_LEN]u8 = undefined;
        try encryptKey(allocator, private_key_64, password, salt, nonce, &adria_keypair.public_key, &encrypted_key);

        return WalletFile{
            .version = 2,
            .salt = salt,
            .nonce = nonce,
            .encrypted_private_key = encrypted_key,
            .public_key = adria_keypair.public_key,
            .address = address,
        };
    }

    /// Decrypt private key from wallet file.
    /// Returns error.InvalidPassword if the AEAD tag fails (wrong password or corruption).
    pub fn decryptPrivateKey(self: *const WalletFile, allocator: std.mem.Allocator, password: []const u8) ![64]u8 {
        if (self.version != 2) return error.OutdatedWalletFormat;

        var private_key: [64]u8 = undefined;
        try decryptKey(allocator, self.encrypted_private_key, password, self.salt, self.nonce, &self.public_key, &private_key);
        return private_key;
    }
};

/// Adria Wallet Manager
pub const Wallet = struct {
    allocator: std.mem.Allocator,
    private_key: ?[64]u8,
    public_key: ?[32]u8,
    address: ?types.Address,

    pub fn init(allocator: std.mem.Allocator) Wallet {
        return Wallet{
            .allocator = allocator,
            .private_key = null,
            .public_key = null,
            .address = null,
        };
    }

    pub fn deinit(self: *Wallet) void {
        if (self.private_key) |*priv_key| {
            std.crypto.utils.secureZero(u8, priv_key);
        }
    }

    pub fn createNew(self: *Wallet) !void {
        const adria_keypair = try key.KeyPair.generateUnsignedKey();
        const address = util.hash256(&adria_keypair.public_key);
        self.private_key = adria_keypair.private_key;
        self.public_key = adria_keypair.public_key;
        self.address = address;
    }

    pub fn saveToFile(self: *Wallet, file_path: []const u8, password: []const u8) !void {
        if (self.private_key == null) return error.NoWalletLoaded;

        const private_key_64 = self.private_key.?;
        const wallet_file = try WalletFile.fromPrivateKey(private_key_64, password, self.allocator);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        try file.writeAll(std.mem.asBytes(&wallet_file));
    }

    pub fn loadFromFile(self: *Wallet, file_path: []const u8, password: []const u8) !void {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.WalletFileNotFound,
            else => return err,
        };
        defer file.close();

        var wallet_file: WalletFile = undefined;
        const bytes_read = try file.readAll(std.mem.asBytes(&wallet_file));

        if (bytes_read != @sizeOf(WalletFile)) {
            // Check if this looks like an old v1 wallet (180 bytes)
            if (bytes_read == 180) return error.OutdatedWalletFormat;
            return error.InvalidWalletFile;
        }

        if (wallet_file.version != 2) return error.OutdatedWalletFormat;

        const private_key_64 = wallet_file.decryptPrivateKey(self.allocator, password) catch |err| switch (err) {
            error.InvalidPassword => return error.InvalidPassword,
            error.OutdatedWalletFormat => return error.OutdatedWalletFormat,
            else => return err,
        };

        const adria_keypair = key.KeyPair.fromPrivateKey(private_key_64);
        self.private_key = adria_keypair.private_key;
        self.public_key = adria_keypair.public_key;
        self.address = deriveAddress(adria_keypair.public_key);
    }

    pub fn signTransaction(self: *Wallet, tx_hash: *const types.Hash) !types.Signature {
        if (self.private_key == null) return error.NoWalletLoaded;
        const adria_keypair = self.getAdriaKeyPair() orelse return error.NoWalletLoaded;
        return adria_keypair.signTransaction(tx_hash.*) catch return error.NoWalletLoaded;
    }

    pub fn getAddress(self: *Wallet) ?types.Address {
        return self.address;
    }

    pub fn getPublicKey(self: *Wallet) ?[32]u8 {
        return self.public_key;
    }

    pub fn isLoaded(self: *Wallet) bool {
        return self.private_key != null;
    }

    pub fn getAdriaKeyPair(self: *Wallet) ?key.KeyPair {
        if (self.private_key == null or self.public_key == null) return null;
        return key.KeyPair{
            .private_key = self.private_key.?,
            .public_key = self.public_key.?,
        };
    }

    pub fn getAddressHex(self: *Wallet, allocator: std.mem.Allocator) !?[]u8 {
        if (self.address == null) return null;
        return try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&self.address.?)});
    }

    pub fn getShortAddressHex(self: *Wallet) ?[16]u8 {
        if (self.address == null) return null;
        var short_addr: [16]u8 = undefined;
        const hex_slice = std.fmt.fmtSliceHexLower(self.address.?[0..8]);
        _ = std.fmt.bufPrint(&short_addr, "{s}", .{hex_slice}) catch return null;
        return short_addr;
    }

    pub fn fileExists(file_path: []const u8) bool {
        const file = std.fs.cwd().openFile(file_path, .{}) catch return false;
        file.close();
        return true;
    }
};

// === INTERNAL FUNCTIONS ===

fn deriveAddress(public_key: [32]u8) types.Address {
    return util.hash256(&public_key);
}

/// Derive a 32-byte encryption key from password + salt using Argon2id.
fn deriveKey(allocator: std.mem.Allocator, password: []const u8, salt: [32]u8, out_key: *[KEY_LEN]u8) !void {
    try std.crypto.pwhash.argon2.kdf(
        allocator,
        out_key,
        password,
        &salt,
        .{ .t = ARGON2_TIME_COST, .m = ARGON2_MEM_COST_KB, .p = ARGON2_PARALLELISM },
        .argon2id,
    );
}

/// Encrypt a 64-byte Ed25519 private key.
/// Output is 80 bytes: [64 ciphertext | 16 Poly1305 tag].
/// The public_key is used as AEAD additional data, binding the ciphertext to this wallet identity.
fn encryptKey(
    allocator: std.mem.Allocator,
    private_key: [PRIVKEY_LEN]u8,
    password: []const u8,
    salt: [32]u8,
    nonce: [NONCE_LEN]u8,
    public_key: *const [32]u8,
    output: *[CIPHERTEXT_LEN]u8,
) !void {
    var key_material: [KEY_LEN]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key_material);
    try deriveKey(allocator, password, salt, &key_material);

    var tag: [TAG_LEN]u8 = undefined;
    ChaCha.encrypt(output[0..PRIVKEY_LEN], &tag, &private_key, public_key, nonce, key_material);
    @memcpy(output[PRIVKEY_LEN..], &tag);
}

/// Decrypt a 64-byte Ed25519 private key.
/// Returns error.InvalidPassword if the AEAD authentication tag does not match
/// (wrong password, wrong additional data, or corrupted ciphertext).
fn decryptKey(
    allocator: std.mem.Allocator,
    encrypted: [CIPHERTEXT_LEN]u8,
    password: []const u8,
    salt: [32]u8,
    nonce: [NONCE_LEN]u8,
    public_key: *const [32]u8,
    output: *[PRIVKEY_LEN]u8,
) !void {
    var key_material: [KEY_LEN]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key_material);
    try deriveKey(allocator, password, salt, &key_material);

    const tag: [TAG_LEN]u8 = encrypted[PRIVKEY_LEN..].*;
    ChaCha.decrypt(output, encrypted[0..PRIVKEY_LEN], tag, public_key, nonce, key_material) catch {
        return error.InvalidPassword;
    };
}
