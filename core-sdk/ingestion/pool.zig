const std = @import("std");
const types = @import("common").types;
const main = @import("../main.zig");
const print = std.debug.print;

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
    adria: *main.Adria,

    const MAX_QUEUE_SIZE: usize = 10000;

    pub fn init(allocator: std.mem.Allocator, adria: *main.Adria, num_threads: usize) !*IngestionPool {
        const self = try allocator.create(IngestionPool);
        self.allocator = allocator;
        self.tasks = std.ArrayList(VerificationTask).init(allocator);
        self.mutex = .{};
        self.cond = .{};
        self.should_stop = std.atomic.Value(bool).init(false);
        self.adria = adria;

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

                // Pop from front (FIFO)
                task = self.tasks.swapRemove(0);
                self.mutex.unlock();
            }

            // 2. Verify (CPU Intense)
            // This runs in parallel across all workers
            const is_valid = self.adria.validateTransaction(task.raw_tx) catch false;

            // 3. Commit or Reject
            if (is_valid) {
                // Add to mempool (Requires Lock, but quick)
                // We use a new internal method that skips validation
                self.adria.addVerifiedTransaction(task.raw_tx) catch {
                    // Fail (Mempool full?)
                    const msg = "ERROR: Mempool full or error\n";
                    // Fix: Free payload if mempool rejects it
                    self.adria.allocator.free(task.raw_tx.payload);
                    task.connection.stream.writeAll(msg) catch {};
                    continue;
                };

                const msg = "CLIENT_TRANSACTION_ACCEPTED\n";
                task.connection.stream.writeAll(msg) catch {};
            } else {
                std.debug.print("[ERROR] Transaction Validation Failed. Rejecting!\n", .{});
                const msg = "ERROR: Invalid Transaction (Signature/Format)\n";
                // Fix: Free payload if validation fails
                self.adria.allocator.free(task.raw_tx.payload);
                task.connection.stream.writeAll(msg) catch {};
            }
        }
    }
};
