const std = @import("std");
const zga = @import("ZGA");

pub fn main() !void {
    // create heap allocato
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // creating watchdog
    const wd: zga.ZGA_WATCHDOG = try zga.createWatchdog();
    try zga.initWatchdog(&wd, alloc);
}