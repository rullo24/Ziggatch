const std = @import("std");
const zga = @import("zga");

pub fn main() !void {
    // allocator creation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer gpa.deinit();

    // creating watchdog
    const temp = zga.createWatchdog(alloc);
    try temp.init(alloc);

    defer temp.deinit();
}