// consensus/interface.zig - Consensus Interface Definitions

const std = @import("std");
const types = @import("common").types;

/// Types of Consensus Engines
pub const ConsensusType = enum {
    Solo,
    // Raft,
    // PBFT, ...
};

/// The public interface for any Consensus implementation.
/// Uses Zig's manual VTable pattern for dynamic dispatch.
pub const Consenter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Start the consensus engine (background threads, listeners)
        start: *const fn (ctx: *anyopaque) anyerror!void,

        /// Stop the consensus engine
        stop: *const fn (ctx: *anyopaque) void,

        /// Receive a transaction from a client/peer
        /// The consenter is responsible for ordering it into a block eventually.
        recvTransaction: *const fn (ctx: *anyopaque, tx: types.Transaction) anyerror!void,
    };

    /// Start the engine
    pub fn start(self: Consenter) !void {
        return self.vtable.start(self.ptr);
    }

    /// Stop the engine
    pub fn stop(self: Consenter) void {
        return self.vtable.stop(self.ptr);
    }

    /// Submit a transaction to be ordered
    pub fn recvTransaction(self: Consenter, tx: types.Transaction) !void {
        return self.vtable.recvTransaction(self.ptr, tx);
    }
};
