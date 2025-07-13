const std = @import("std");
const zga = @import("ZGA");
const inotify = @import("../../src/_inotify.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    // Setup and init watchdog
    var wd: zga.ZGA_WATCHDOG = .{};
    defer wd.deinit();
    try inotify.watchdogInit(&wd.platform_vars, alloc);

    // Add watch to trigger events (create and delete)
    try inotify.watchdogAdd(&wd.platform_vars, "../../test", zga.ZGA_DELETE | zga.ZGA_CREATE);

    // creating buffers for valid watchdogRead
    var event_buf: [zga.SIZE_EVENT_QUEUE]zga.ZGA_EVENT = undefined;
    var error_buf: [zga.SIZE_ERROR_QUEUE]anyerror = undefined;
    var event_queue = std.fifo.LinearFifo(zga.ZGA_EVENT, .Slice).init(&event_buf); // init the LinearFIFO 
    var error_queue = std.fifo.LinearFifo(anyerror, .Slice).init(&error_buf); // init the LinearFIFO 

    // Create file and then delete it in "./test" directory --> should be seen and captured by watcher
    var cwd: std.fs.Dir = std.fs.cwd();
    const p_file = try cwd.createFile("../../test/wd_read_test_file_987654321.txt", .{});
    defer p_file.close();
    try cwd.deleteFile("../../test/wd_read_test_file_987654321.txt");

    // Call watchdogRead to process events
    try inotify.watchdogRead(&wd.platform_vars, zga.ZGA_DELETE | zga.ZGA_CREATE, &event_queue, &error_queue);

    const create_event = event_queue.readItem().?;
    const delete_event = event_queue.readItem().?;

    std.debug.print("{s}\n", .{create_event.name_buf[0..create_event.name_len]});
    std.debug.print("{s}\n", .{delete_event.name_buf[0..delete_event.name_len]});

}