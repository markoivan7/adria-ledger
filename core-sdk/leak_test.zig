const std = @import("std");
const testing = std.testing;
const types = @import("common").types;
const solo = @import("consensus").solo;
const db = @import("execution").db;
const util = @import("common").util;

test "transaction payload memory lifecycle" {
    // 1. Setup
    const allocator = testing.allocator;

    // Create Test DB
    // Use unique directory
    const test_dir = "test_leak_data_" ++ "12345"; // simplified
    var database = try db.Database.init(allocator, test_dir);
    defer {
        database.deinit();
        std.fs.cwd().deleteTree(test_dir) catch {};
    }

    // Create Solo Orderer
    var orderer = try solo.SoloOrderer.init(allocator, &database, null);

    // 2. Allocate Payload
    const payload_size = 1024;
    const payload = try allocator.alloc(u8, payload_size);
    // Fill with pattern
    @memset(payload, 0xAA);

    // 3. Create Transaction taking ownership of payload
    const tx = types.Transaction{
        .type = .invoke,
        .sender = [_]u8{0} ** 32,
        .recipient = [_]u8{0} ** 32,
        .payload = payload, // Ownership transferred here
        .nonce = 1,
        .timestamp = 0,
        .sender_public_key = [_]u8{0} ** 32,
        .signature = [_]u8{0} ** 64,
        .sender_cert = [_]u8{0} ** 64,
        .network_id = 1,
    };

    // 4. Submit to Orderer
    try orderer.consenter().recvTransaction(tx);

    // 5. Cleanup
    // Calling deinit should now free the payload in mempool
    orderer.deinit();

    // If we reach here without leak report from testing.allocator, we passed!
}
