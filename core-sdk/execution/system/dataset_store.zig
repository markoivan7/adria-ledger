const std = @import("std");
const chaincode = @import("../chaincode.zig");
const json_canon = @import("json_canon.zig");
const util = @import("common").util;

pub const DatasetStore = struct {
    pub const ID = "dataset_store";

    pub fn invoke(stub: *chaincode.Stub, function: []const u8, args: [][]const u8) ![]u8 {
        if (std.mem.eql(u8, function, "append_snapshot_chunk")) {
            return appendSnapshotChunk(stub, args);
        } else if (std.mem.eql(u8, function, "commit_snapshot")) {
            return commitSnapshot(stub, args);
        } else {
            return chaincode.ChaincodeError.InvalidFunction;
        }
    }

    fn appendSnapshotChunk(stub: *chaincode.Stub, args: [][]const u8) ![]u8 {
        if (args.len != 3) return chaincode.ChaincodeError.InvalidArguments;
        const dataset_id = args[0];
        const snapshot_id = args[1];
        const chunk_json = args[2];
        _ = dataset_id; // Will use it to validate or reference later if needed
        _ = snapshot_id;

        var chunk_parsed = std.json.parseFromSlice(std.json.Value, stub.allocator, chunk_json, .{}) catch return chaincode.ChaincodeError.InvalidArguments;
        defer chunk_parsed.deinit();

        if (chunk_parsed.value != .array) return chaincode.ChaincodeError.InvalidArguments;

        // Iterate over rows to validate and canonicalize, but drop from state to keep engine fast and lightweight
        for (chunk_parsed.value.array.items) |row| {
            if (row != .object) return chaincode.ChaincodeError.InvalidArguments;

            // Generate canonical format of this specific row
            const canon_str = json_canon.canonicalizeValue(stub.allocator, row) catch return chaincode.ChaincodeError.InvalidArguments;
            defer stub.allocator.free(canon_str);

            // Hash the canonical payload
            const hash_val = util.hash(canon_str);
            const hash_hex = util.hexStr(stub.allocator, &hash_val, false) catch return chaincode.ChaincodeError.InvalidArguments;
            _ = hash_hex; // Validation only, we don't store the row or hash in state DB
        }

        return stub.allocator.dupe(u8, "CHUNK_APPENDED");
    }

    fn commitSnapshot(stub: *chaincode.Stub, args: [][]const u8) ![]u8 {
        // args: dataset_id, snapshot_id, metadata_json
        if (args.len != 3) return chaincode.ChaincodeError.InvalidArguments;
        const dataset_id = args[0];
        const snapshot_id = args[1];
        const meta_json = args[2];

        const meta_key = try std.fmt.allocPrint(stub.allocator, "DATASET_META_{s}", .{snapshot_id});
        defer stub.allocator.free(meta_key);

        const head_key = try std.fmt.allocPrint(stub.allocator, "DATASET_HEAD_{s}", .{dataset_id});
        defer stub.allocator.free(head_key);

        // 1. Write metadata (Data itself is dropped from state and kept only in WAL)
        try stub.putState(meta_key, meta_json);

        // 2. Update HEAD for this dataset
        try stub.putState(head_key, snapshot_id);

        return stub.allocator.dupe(u8, "SNAPSHOT_COMMITTED");
    }
};
