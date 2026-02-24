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
        _ = dataset_id; // Will use it to validate or reference later if needed, but pending uses snapshot_id

        var chunk_parsed = std.json.parseFromSlice(std.json.Value, stub.allocator, chunk_json, .{}) catch return chaincode.ChaincodeError.InvalidArguments;
        defer chunk_parsed.deinit();

        if (chunk_parsed.value != .array) return chaincode.ChaincodeError.InvalidArguments;

        // We need to load existing PENDING list, or create new if not exists
        const pending_key = try std.fmt.allocPrint(stub.allocator, "DATASET_PENDING_{s}", .{snapshot_id});
        defer stub.allocator.free(pending_key);

        var existing_rows = std.ArrayList(std.json.Value).init(stub.allocator);
        defer existing_rows.deinit();

        // Need to parse state to memory since std.json.Value tree needs dynamic lifetimes
        // We will read and construct a merged array.
        const val_opt = try stub.getState(pending_key);
        if (val_opt) |val| {
            var existing_parsed = std.json.parseFromSlice(std.json.Value, stub.allocator, val, .{}) catch return chaincode.ChaincodeError.InvalidArguments;
            defer existing_parsed.deinit();
            stub.allocator.free(val);
            if (existing_parsed.value == .array) {
                // Must clone to keep values alive, as existing_parsed will be deinit.
                // Or just keep it simpler - append chunks locally isn't cheap dynamically.
                // Actually an easier way is just string concatenation: "[...]"
                // Remove the last ']' and append ', {new_row}'
            }
        }

        // Simpler string-based chunk appending logic to avoid deep-allocating JSON trees repeatedly:
        // Wait, we need to Canonicalize the NEW rows anyway! Let's just process the chunk first.

        var processed_array = std.json.Value{ .array = std.ArrayList(std.json.Value).init(stub.allocator) };
        defer processed_array.array.deinit();

        for (chunk_parsed.value.array.items) |row| {
            if (row != .object) return chaincode.ChaincodeError.InvalidArguments;

            // Generate canonical format of this specific row
            const canon_str = json_canon.canonicalizeValue(stub.allocator, row) catch return chaincode.ChaincodeError.InvalidArguments;
            defer stub.allocator.free(canon_str);

            // Hash the canonical payload
            const hash_val = util.hash(canon_str);
            const hash_hex = util.hexStr(stub.allocator, &hash_val, false) catch return chaincode.ChaincodeError.InvalidArguments;
            // Note: hash_hex leaks unless we tie it to an arena, but stub.allocator is usually an arena for transaction scope.

            // Reconstruct a row with _hash inside
            var new_obj = row;
            try new_obj.object.put("_hash", std.json.Value{ .string = hash_hex });

            try processed_array.array.append(new_obj);

            // We can also store DATASET_ROW_{hash} if we wanted Hybrid Model, but User explicitly said Fully On-Chain storage.
            // The row payload is fully contained in this processed_array.
        }

        const new_chunk_str = std.json.stringifyAlloc(stub.allocator, processed_array, .{}) catch return chaincode.ChaincodeError.InvalidArguments;
        defer stub.allocator.free(new_chunk_str);

        // String-based merge with existing pending chunk
        var final_str = std.ArrayList(u8).init(stub.allocator);
        defer final_str.deinit();

        const pending_val_opt = try stub.getState(pending_key);
        if (pending_val_opt) |pending_val| {
            defer stub.allocator.free(pending_val);
            if (pending_val.len > 2 and pending_val[0] == '[' and pending_val[pending_val.len - 1] == ']') {
                // Remove trailing ']' from old
                try final_str.appendSlice(pending_val[0 .. pending_val.len - 1]);
                if (pending_val.len > 2 and new_chunk_str.len > 2) {
                    try final_str.append(',');
                }
                // Remove leading '[' from new
                try final_str.appendSlice(new_chunk_str[1..]);
            } else {
                try final_str.appendSlice(new_chunk_str);
            }
        } else {
            try final_str.appendSlice(new_chunk_str);
        }

        // Store back
        try stub.putState(pending_key, final_str.items);

        return stub.allocator.dupe(u8, "CHUNK_APPENDED");
    }

    fn commitSnapshot(stub: *chaincode.Stub, args: [][]const u8) ![]u8 {
        // args: dataset_id, snapshot_id, metadata_json
        if (args.len != 3) return chaincode.ChaincodeError.InvalidArguments;
        const dataset_id = args[0];
        const snapshot_id = args[1];
        const meta_json = args[2];

        const pending_key = try std.fmt.allocPrint(stub.allocator, "DATASET_PENDING_{s}", .{snapshot_id});
        defer stub.allocator.free(pending_key);

        const data_key = try std.fmt.allocPrint(stub.allocator, "DATASET_DATA_{s}", .{snapshot_id});
        defer stub.allocator.free(data_key);

        const meta_key = try std.fmt.allocPrint(stub.allocator, "DATASET_META_{s}", .{snapshot_id});
        defer stub.allocator.free(meta_key);

        const head_key = try std.fmt.allocPrint(stub.allocator, "DATASET_HEAD_{s}", .{dataset_id});
        defer stub.allocator.free(head_key);

        // 1. Move pending to actual data
        const pending_val = try stub.getState(pending_key);
        if (pending_val) |val| {
            defer stub.allocator.free(val);
            try stub.putState(data_key, val);
            // Optionally clear pending, but stub.putState doesn't delete easily. We can just leave it or set to null.
        } else {
            // Empty snapshot (e.g. 0 rows)
            try stub.putState(data_key, "[]");
        }

        // 2. Write metadata
        try stub.putState(meta_key, meta_json);

        // 3. Update HEAD for this dataset
        try stub.putState(head_key, snapshot_id);

        return stub.allocator.dupe(u8, "SNAPSHOT_COMMITTED");
    }
};
