const std = @import("std");
const zga = @import("ZGA");

pub fn main() !void {
    // allocator creation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer gpa.deinit();

    // creating watchdog
    const temp = try zga.createWatchdog(alloc);
    _ = temp;
}