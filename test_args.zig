const std = @import("std");
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    
    _ = args.next();
    
    var is_orderer = false;
    while (args.next()) |arg| {
        std.debug.print("Arg: {s}\n", .{arg});
        if (std.mem.eql(u8, arg, "--orderer")) {
            is_orderer = true;
        }
    }
    std.debug.print("Is Orderer: {}\n", .{is_orderer});
}
