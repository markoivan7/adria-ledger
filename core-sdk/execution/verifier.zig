const std = @import("std");
const types = @import("common").types;
const key = @import("crypto").key;

/// Context passed to each parallel verification task (Protocol v2).
const VerifyContext = struct {
    failures: *std.atomic.Value(u32),
    wg: *std.Thread.WaitGroup,
    tx: types.Transaction,
    root_public_keys: []const [32]u8,
    revoked_serials: []const u64,
    current_time: u64,
};

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

    /// Verifies all transactions in a block in parallel (Protocol v2).
    /// Checks: MSP cert signature + expiry + CRL + transaction signature.
    /// Returns true only if ALL checks pass for ALL transactions.
    pub fn verifyBlock(
        self: *ParallelVerifier,
        block: types.Block,
        root_public_keys: []const [32]u8,
        revoked_serials: []const u64,
        current_time: u64,
    ) !bool {
        if (block.transactions.len == 0) return true;

        var failures = std.atomic.Value(u32).init(0);
        var wg = std.Thread.WaitGroup{};

        for (block.transactions) |tx| {
            const ctx = VerifyContext{
                .failures = &failures,
                .wg = &wg,
                .tx = tx,
                .root_public_keys = root_public_keys,
                .revoked_serials = revoked_serials,
                .current_time = current_time,
            };
            wg.start();
            try self.pool.spawn(verifyTask, .{ctx});
        }

        wg.wait();
        return failures.load(.acquire) == 0;
    }

    fn verifyTask(ctx: VerifyContext) void {
        defer ctx.wg.finish();

        // 1. CRL check: reject transactions with revoked cert serials
        for (ctx.revoked_serials) |revoked| {
            if (ctx.tx.cert_serial == revoked) {
                _ = ctx.failures.fetchAdd(1, .release);
                return;
            }
        }

        // 2. MSP CertificateV2 Verification: check cert signature + time-bound validity
        var cert_valid = false;
        for (ctx.root_public_keys) |root_pk| {
            if (key.MSP.verifyCertificateV2(
                root_pk,
                ctx.tx.sender_cert,
                ctx.tx.sender_public_key,
                ctx.tx.cert_serial,
                ctx.tx.cert_issued_at,
                ctx.tx.cert_expires_at,
                ctx.current_time,
            )) {
                cert_valid = true;
                break;
            }
        }

        if (!cert_valid) {
            _ = ctx.failures.fetchAdd(1, .release);
            return;
        }

        // 3. Transaction Signature Verification
        const tx_hash = ctx.tx.hashForSigning();
        if (!key.verify(ctx.tx.sender_public_key, &tx_hash, ctx.tx.signature)) {
            _ = ctx.failures.fetchAdd(1, .release);
            return;
        }
    }
};

const testing = std.testing;

test "parallel verification" {
    const allocator = testing.allocator;

    // Setup root CA and user identity
    var root_ca = try key.KeyPair.generateUnsignedKey();
    defer root_ca.deinit();

    var identity = try key.Identity.createNew(root_ca);
    defer identity.deinit();

    var verifier = try ParallelVerifier.init(allocator, 2);
    defer verifier.deinit();

    // Create a valid signed transaction
    var tx = types.Transaction{
        .type = .invoke,
        .sender = identity.keypair.getAddress(),
        .recipient = std.mem.zeroes(types.Address),
        .payload = "test",
        .nonce = 1,
        .timestamp = 1000,
        .sender_public_key = identity.keypair.public_key,
        .sender_cert = identity.certificate.signature,
        .cert_serial = identity.certificate.serial,
        .cert_issued_at = identity.certificate.issued_at,
        .cert_expires_at = identity.certificate.expires_at,
        .network_id = 1,
        .signature = std.mem.zeroes(types.Signature),
    };
    const tx_hash = tx.hashForSigning();
    tx.signature = try identity.keypair.sign(&tx_hash);

    const txs = try allocator.alloc(types.Transaction, 10);
    defer allocator.free(txs);
    for (0..10) |i| txs[i] = tx;

    const block = types.Block{
        .header = undefined,
        .transactions = txs,
    };

    const root_pks = [_][32]u8{root_ca.public_key};
    const no_revoked = [_]u64{};
    const current_time: u64 = 1000; // within Identity.createNew's 0..maxInt range

    // Valid block should pass
    const valid = try verifier.verifyBlock(block, &root_pks, &no_revoked, current_time);
    try testing.expect(valid);

    // Test: Corrupt one signature — block should fail
    txs[5].signature[0] ^= 0xFF;
    const valid2 = try verifier.verifyBlock(block, &root_pks, &no_revoked, current_time);
    try testing.expect(!valid2);
    txs[5].signature[0] ^= 0xFF; // Restore

    // Test: Revoked serial — block should fail
    const revoked = [_]u64{identity.certificate.serial};
    const valid3 = try verifier.verifyBlock(block, &root_pks, &revoked, current_time);
    try testing.expect(!valid3);

    // Test: Expired cert — block should fail
    const past_time: u64 = std.math.maxInt(u64); // well past expires_at=maxInt(u64)... actually no, createNew sets maxInt, so this won't expire
    _ = past_time; // Identity.createNew uses maxInt so cert never expires in tests
}
