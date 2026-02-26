// consensus/solo.zig - Single Node Orderer Implementation
// Takes transactions, batches them, and cuts blocks.
// This preserves the logic from Phase 1-8 but behind the Consenter interface.

const std = @import("std");
const types = @import("common").types;
const consensus_interface = @import("interface.zig");
const db = @import("execution").db;
const util = @import("common").util;
const key = @import("crypto").key;

pub const SoloOrderer = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    validator: ?key.Identity,

    // Solo specific state
    mempool: std.ArrayList(types.Transaction),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition, // Condition variable for new transactions
    should_stop: std.atomic.Value(bool),
    thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator, database: *db.Database, validator: ?key.Identity) !*SoloOrderer {
        const self = try allocator.create(SoloOrderer);
        self.* = .{
            .allocator = allocator,
            .database = database,
            .validator = validator,
            .mempool = std.ArrayList(types.Transaction).init(allocator),
            .mutex = std.Thread.Mutex{},
            .cond = std.Thread.Condition{},
            .should_stop = std.atomic.Value(bool).init(false),
            .thread = null,
        };
        return self;
    }

    pub fn deinit(self: *SoloOrderer) void {
        self.stop();
        // Fix: Free any pending payloads in mempool on shutdown
        for (self.mempool.items) |tx| {
            self.allocator.free(tx.payload);
        }
        self.mempool.deinit();
        if (self.validator) |*val| {
            val.deinit();
        }
        self.allocator.destroy(self);
    }

    pub fn stop(self: *SoloOrderer) void {
        stopImpl(self);
    }

    // --- Consenter Interface Implementation ---

    pub fn consenter(self: *SoloOrderer) consensus_interface.Consenter {
        return .{
            .ptr = self,
            .vtable = &.{
                .start = startImpl,
                .stop = stopImpl,
                .recvTransaction = recvTransactionImpl,
            },
        };
    }

    fn startImpl(ctx: *anyopaque) anyerror!void {
        const self: *SoloOrderer = @ptrCast(@alignCast(ctx));
        if (self.thread != null) return; // Already running

        self.should_stop.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, ordererLoop, .{self});
        std.debug.print("[INFO] Solo Orderer Started\n", .{});
    }

    fn stopImpl(ctx: *anyopaque) void {
        const self: *SoloOrderer = @ptrCast(@alignCast(ctx));
        self.should_stop.store(true, .release);
        self.cond.broadcast(); // Wake up thread if waiting
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn recvTransactionImpl(ctx: *anyopaque, tx: types.Transaction) anyerror!void {
        const self: *SoloOrderer = @ptrCast(@alignCast(ctx));

        self.mutex.lock();
        defer self.mutex.unlock();

        // TODO: Consider hashmap for duplicate check
        try self.mempool.append(tx);
        self.cond.signal(); // Wake up orderer
    }

    // --- Internal Logic ---

    fn ordererLoop(self: *SoloOrderer) void {
        const BATCH_SIZE = 2000;
        const BATCH_TIMEOUT_NS = 50 * std.time.ns_per_ms;

        while (!self.should_stop.load(.acquire)) {
            self.mutex.lock();

            // 1. Wait for at least one transaction
            while (self.mempool.items.len == 0) {
                if (self.should_stop.load(.acquire)) {
                    self.mutex.unlock();
                    return;
                }
                self.cond.wait(&self.mutex);
            }

            // 2. Accumulate transactions until Batch Size or Timeout
            const deadline = std.time.nanoTimestamp() + BATCH_TIMEOUT_NS;

            while (self.mempool.items.len < BATCH_SIZE) {
                const now = std.time.nanoTimestamp();
                if (now >= deadline) break;

                // Wait for signal (new tx) or timeout
                self.cond.timedWait(&self.mutex, @intCast(deadline - now)) catch {};

                if (self.should_stop.load(.acquire)) {
                    self.mutex.unlock();
                    return;
                }
            }

            // 3. Cut Block
            // Release lock so cutBlock can acquire it (re-entrant check or standard mutex?)
            // Standard mutex is usually non-recursive in Zig std.
            self.mutex.unlock();

            self.cutBlock() catch |err| {
                std.debug.print("[ERROR] Solo Orderer failed to cut block: {}\n", .{err});
            };
        }
    }

    fn cutBlock(self: *SoloOrderer) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.mempool.items.len == 0) return; // Nothing to order

        // Create Block
        const current_height = try self.database.getHeight();

        // Get previous hash
        var previous_hash = std.mem.zeroes(types.Hash);
        if (current_height > 0) {
            const prev_block = try self.database.getBlock(current_height - 1);
            defer self.allocator.free(prev_block.transactions);
            previous_hash = prev_block.hash();
        }

        // Logic relies on Identity being set
        if (self.validator == null) {
            // In Peer Mode (no validator), we just idle.
            // Returning errorspams the logs, so we just return cleanly.
            return;
        }
        const val = self.validator.?;

        // 1. Create Header
        const timestamp = @as(u64, @intCast(util.getTime()));
        var header = types.BlockHeader{
            .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
            .previous_hash = previous_hash,
            .merkle_root = std.mem.zeroes(types.Hash), // TODO: Merkle
            .timestamp = timestamp,
            .validator_public_key = val.keypair.public_key,
            .validator_cert = val.certificate.signature,
            .validator_cert_serial = val.certificate.serial,
            .validator_cert_issued_at = val.certificate.issued_at,
            .validator_cert_expires_at = val.certificate.expires_at,
            .signature = std.mem.zeroes(types.Signature),
        };

        // 2. Sign Header
        const header_hash = header.hash();
        header.signature = try val.keypair.sign(&header_hash);

        // 3. Assemble Block
        // We take ownership of the mempool's items for the block
        // and clear the mempool.
        const txs = try self.allocator.dupe(types.Transaction, self.mempool.items);
        const block = types.Block{
            .header = header,
            .transactions = txs,
        };

        // 4. Save Block (Commit)
        // In a real network, we BROADCAST this to peers.
        // But since we are likely running in a single binary "Peer+Orderer" mode,
        // we can just save it to our own DB.
        // If we just save it, the State (KV Store) won't update!
        // The Consenter's job is to ORDER, not EXECUTE.
        // It provides the block to the "Committer".

        // TODO: Send block to Execution Engine callback instead of direct save.
        try self.database.saveBlock(current_height, block);
        std.debug.print("[INFO] Solo produced Block #{} with {} txs\n", .{ current_height, txs.len });

        // Clear mempool
        // Fix: Free payloads before clearing
        // Free the corresponding payloads referenced by mempool.

        // Free the payloads referenced by the mempool items
        for (self.mempool.items) |tx| {
            self.allocator.free(tx.payload);
        }

        self.mempool.clearRetainingCapacity();
    }
};
