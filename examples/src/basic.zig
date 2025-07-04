const std = @import("std");
const zga = @import("ZGA");

pub fn main() !void {
    // create heap allocato
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // creating watchdog
    var wd: zga.ZGA_WATCHDOG = .{}; 
    try wd.init(alloc);
    defer wd.close() catch {};
}