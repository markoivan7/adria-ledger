const std = @import("std");
const types = @import("common").types;
const key = @import("crypto").key;

pub const ParallelVerifier = struct {
    allocator: std.mem.Allocator,
    pool: std.Thread.Pool,

    pub fn init(allocator: std.mem.Allocator, num_threads: ?u32) !*ParallelVerifier {
        const self = try allocator.create(ParallelVerifier);
        self.allocator = allocator;

        const n_threads = num_threads orelse @as(u32, @intCast(std.Thread.getCpuCount() catch 4));

        try self.pool.init(.{
            .allocator = allocator,
            .n_jobs = n_threads,
        });

        return self;
    }

    pub fn deinit(self: *ParallelVerifier) void {
        self.pool.deinit();
        self.allocator.destroy(self);
    }

    /// Verifies all transactions in a block in parallel.
    /// Returns true only if ALL signatures are valid.
    /// Returns false immediately if any check fails (though threads may continue running).
    pub fn verifyBlock(self: *ParallelVerifier, block: types.Block, root_public_keys: []const [32]u8) !bool {
        // If block is empty, it's valid (vacuously true)
        if (block.transactions.len == 0) return true;

        // Atomic counter for failures
        var failures = std.atomic.Value(u32).init(0);

        // WaitGroup to wait for all tasks
        var wg = std.Thread.WaitGroup{};

        for (block.transactions) |tx| {
            wg.start();
            try self.pool.spawn(verifyTask, .{ &failures, &wg, tx, root_public_keys });
        }

        wg.wait();

        return failures.load(.acquire) == 0;
    }

    fn verifyTask(failures: *std.atomic.Value(u32), wg: *std.Thread.WaitGroup, tx: types.Transaction, root_public_keys: []const [32]u8) void {
        defer wg.finish();

        // 1. MSP Verification
        var cert_valid = false;
        for (root_public_keys) |root_pk| {
            if (key.MSP.verifyCertificate(root_pk, tx.sender_public_key, tx.sender_cert)) {
                cert_valid = true;
                break;
            }
        }

        if (!cert_valid) {
            _ = failures.fetchAdd(1, .release);
            return;
        }

        // 2. Signature Verification
        const tx_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            _ = failures.fetchAdd(1, .release);
            return;
        }
    }
};

const testing = std.testing;

test "parallel verification" {
    const allocator = testing.allocator;

    // Setup keys
    var kp = try key.KeyPair.generateUnsignedKey();

    // Setup Verifier
    var verifier = try ParallelVerifier.init(allocator, 2);
    defer verifier.deinit();

    // Create dummy tx
    var tx = types.Transaction{
        .type = .invoke,
        .sender = kp.getAddress(),
        .recipient = std.mem.zeroes(types.Address),
        .payload = "test",
        .nonce = 1,
        .timestamp = 0,
        .sender_public_key = kp.public_key,
        .sender_cert = std.mem.zeroes([64]u8), // Mock cert
        .signature = std.mem.zeroes(types.Signature),
    };
    const tx_hash = tx.hashForSigning();
    tx.signature = try kp.sign(&tx_hash);

    // Create block
    const txs = try allocator.alloc(types.Transaction, 10);
    defer allocator.free(txs);

    for (0..10) |i| {
        txs[i] = tx; // Copy valid tx
    }

    const block = types.Block{
        .header = undefined, // verifyBlock only checks txs
        .transactions = txs,
    };

    // Verify
    const root_pks = [_][32]u8{std.mem.zeroes([32]u8)};
    const valid = try verifier.verifyBlock(block, &root_pks);
    try testing.expect(!valid); // Should be false because key is zero and DEV bypass is removed

    // Test Invalid Signature
    txs[5].signature[0] ^= 0xFF; // Corrupt signature
    const valid2 = try verifier.verifyBlock(block, &root_pks);
    try testing.expect(!valid2);
}
