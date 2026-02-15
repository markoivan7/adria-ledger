const std = @import("std");
const types = @import("common").types;
const main = @import("../main.zig");
const print = std.debug.print;

/// A bounded queue for raw transactions waiting to be verified.
/// This prevents OOM attack by strictly limiting pending items.
pub const VerificationTask = struct {
    raw_tx: types.Transaction, // The transaction struct itself (already parsed but unverified)
    connection: std.net.Server.Connection, // To send ACK/NAK
    // We could add a callback or event here
};

pub const IngestionPool = struct {
    allocator: std.mem.Allocator,
    tasks: std.ArrayList(VerificationTask),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    should_stop: std.atomic.Value(bool),
    threads: []std.Thread,
    zeicoin: *main.ZeiCoin,

    const MAX_QUEUE_SIZE: usize = 10000;

    pub fn init(allocator: std.mem.Allocator, zeicoin: *main.ZeiCoin, num_threads: usize) !*IngestionPool {
        const self = try allocator.create(IngestionPool);
        self.allocator = allocator;
        self.tasks = std.ArrayList(VerificationTask).init(allocator);
        self.mutex = .{};
        self.cond = .{};
        self.should_stop = std.atomic.Value(bool).init(false);
        self.zeicoin = zeicoin;

        self.threads = try allocator.alloc(std.Thread, num_threads);
        for (0..num_threads) |i| {
            self.threads[i] = try std.Thread.spawn(.{}, workerLoop, .{self});
        }

        print("[INFO] IngestionPool started with {} workers\n", .{num_threads});
        return self;
    }

    pub fn deinit(self: *IngestionPool) void {
        self.should_stop.store(true, .release);
        self.cond.broadcast(); // Wake all workers

        for (self.threads) |thread| {
            thread.join();
        }

        self.allocator.free(self.threads);
        self.tasks.deinit();
        self.allocator.destroy(self);
    }

    /// Submit a transaction for background verification.
    /// Returns error.QueueFull if the queue is saturated (Backpressure).
    pub fn submit(self: *IngestionPool, task: VerificationTask) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tasks.items.len >= MAX_QUEUE_SIZE) {
            return error.QueueFull;
        }

        try self.tasks.append(task);
        self.cond.signal(); // Wake one worker
    }

    fn workerLoop(self: *IngestionPool) void {
        while (!self.should_stop.load(.acquire)) {
            // 1. Pop Task
            var task: VerificationTask = undefined;
            {
                self.mutex.lock();
                while (self.tasks.items.len == 0) {
                    if (self.should_stop.load(.acquire)) {
                        self.mutex.unlock();
                        return;
                    }
                    self.cond.wait(&self.mutex);
                }

                // Pop from front (FIFO) - slightly inefficient with ArrayList but okay for PoC
                // A CircularBuffer or Deque would be better.
                // For simplified impl, we swapRemove(0) which is O(1) but changes order?
                // No, swapRemove changes order. We want ordered to be nice?
                // Actually, order doesn't matter for independent TXs until they hit the Mempool/Orderer.
                // But client expects ACKs somewhat in order.
                // Let's use orderedRemove(0) which is O(N).
                // Wait, O(N) on 10k items is bad.
                // Let's just use pop() (LIFO) for now? No that's weird.
                // Let's accept swapRemove (Order doesn't matter for non-dependent txs).
                // "Ingestion order" is not "Consensus order".
                task = self.tasks.swapRemove(0);
                self.mutex.unlock();
            }

            // 2. Verify (CPU Intense)
            // This runs in parallel across all workers
            const is_valid = self.zeicoin.validateTransaction(task.raw_tx) catch false;

            // 3. Commit or Reject
            if (is_valid) {
                // Add to mempool (Requires Lock, but quick)
                // We use a new internal method that skips validation
                self.zeicoin.addVerifiedTransaction(task.raw_tx) catch {
                    // Fail (Mempool full?)
                    const msg = "ERROR: Mempool full or error\n";
                    // Fix: Free payload if mempool rejects it
                    self.zeicoin.allocator.free(task.raw_tx.payload);
                    task.connection.stream.writeAll(msg) catch {};
                    continue;
                };

                const msg = "CLIENT_TRANSACTION_ACCEPTED\n";
                task.connection.stream.writeAll(msg) catch {};
            } else {
                const msg = "ERROR: Invalid Transaction (Signature/Format)\n";
                // Fix: Free payload if validation fails
                self.zeicoin.allocator.free(task.raw_tx.payload);
                task.connection.stream.writeAll(msg) catch {};
            }
        }
    }
};
