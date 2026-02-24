const std = @import("std");

/// Canonically serialize a JSON string:
/// 1. Parse JSON into DOM
/// 2. Recursively stringify without any whitespace
/// 3. Sort object keys alphabetically
pub fn canonicalize(allocator: std.mem.Allocator, raw_json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    try stringifyCanonical(parsed.value, out.writer());

    return out.toOwnedSlice();
}

pub fn canonicalizeValue(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    try stringifyCanonical(value, out.writer());

    return out.toOwnedSlice();
}

fn stringifyCanonical(value: std.json.Value, writer: anytype) !void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |i| try writer.print("{}", .{i}),
        .float => {
            // Use scientific notation or standard format, but std.json.stringify logic is preferred.
            // For now, simple format aiming for no trailing zeros or unnecessary points.
            // std.json actually handles this decently well in standard format, but let's emulate it.
            // Actually, we can use std.json's own formatter for raw numbers if we want, or just `{}`.
            try std.json.stringify(value, .{}, writer);
        },
        .number_string => |s| {
            try writer.writeAll(s);
        },
        .string => {
            // Need to escape strings according to JSON spec
            try std.json.stringify(value, .{}, writer);
        },
        .array => |arr| {
            try writer.writeByte('[');
            for (arr.items, 0..) |item, i| {
                if (i > 0) try writer.writeByte(',');
                try stringifyCanonical(item, writer);
            }
            try writer.writeByte(']');
        },
        .object => |obj| {
            try writer.writeByte('{');

            // Extract and sort keys
            var keys = try obj.allocator.alloc([]const u8, obj.count());
            defer obj.allocator.free(keys);

            var iter = obj.iterator();
            var i: usize = 0;
            while (iter.next()) |entry| {
                keys[i] = entry.key_ptr.*;
                i += 1;
            }

            std.sort.block([]const u8, keys, {}, struct {
                fn lessThan(context: void, lhs: []const u8, rhs: []const u8) bool {
                    _ = context;
                    return std.mem.order(u8, lhs, rhs) == .lt;
                }
            }.lessThan);

            for (keys, 0..) |key, idx| {
                if (idx > 0) try writer.writeByte(',');
                // Escape key
                try std.json.stringify(std.json.Value{ .string = key }, .{}, writer);
                try writer.writeByte(':');
                try stringifyCanonical(obj.get(key).?, writer);
            }
            try writer.writeByte('}');
        },
    }
}

test "canonicalize json" {
    const allocator = std.testing.allocator;

    const input1 =
        \\{
        \\  "b": 2,
        \\  "a": 1,
        \\  "c": [3, 2, 1]
        \\}
    ;

    const expected = "{\"a\":1,\"b\":2,\"c\":[3,2,1]}";

    const output1 = try canonicalize(allocator, input1);
    defer allocator.free(output1);

    try std.testing.expectEqualStrings(expected, output1);
}

test "canonicalize nested object" {
    const allocator = std.testing.allocator;

    const input =
        \\{
        \\  "z": {"b": 2, "a": 1},
        \\  "y": "hello"
        \\}
    ;

    const expected = "{\"y\":\"hello\",\"z\":{\"a\":1,\"b\":2}}";

    const out = try canonicalize(allocator, input);
    defer allocator.free(out);

    try std.testing.expectEqualStrings(expected, out);
}
