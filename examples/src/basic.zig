const std = @import("std");
const zga = @import("ZGA");

pub fn main() !void {
    // create heap allocato
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var wd: zga.ZGA_WATCHDOG = .{};
    defer wd.deinit();
    try wd.init(alloc);

    // Add watch to trigger events (create and delete)
    try wd.add(".", zga.ZGA_CREATE | zga.ZGA_DELETE);

    // Create file and then delete it in "./test" directory --> should be seen and captured by watcher
    var cwd: std.fs.Dir = std.fs.cwd();
    const p_file = try cwd.createFile("./wd_read_test_file_987654321.txt", .{});
    defer p_file.close();
    try cwd.deleteFile("./wd_read_test_file_987654321.txt");

    // Call watchdogRead to process events
    try wd.read(zga.ZGA_CREATE | zga.ZGA_DELETE);

    const event1 = try wd.popEvent();
    std.debug.print("{s}\n", .{event1.name_buf});
    std.debug.print("{s} | {d}\n", .{event1.name_buf[0..event1.name_len], event1.zga_flags});

    const event2 = try wd.popEvent();
    std.debug.print("{s}\n", .{event2.name_buf});
    std.debug.print("{s} | {d}\n", .{event2.name_buf[0..event2.name_len], event2.zga_flags});
}