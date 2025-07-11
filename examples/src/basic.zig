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
    defer wd.deinit();

    const example_name: []const u8 = "/home/kali/Desktop/Ziggatch/zig-out/bin";
    const example_flags: comptime_int = zga.ZGA_ACCESSED | zga.ZGA_MODIFIED;
    try wd.add(example_name, example_flags);
    try wd.remove(example_name);
    try wd.add(example_name, example_flags);
    try wd.remove(example_name);
    try wd.add(example_name, example_flags);







}