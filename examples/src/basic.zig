const std = @import("std");
const zga = @import("ZGA");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    // Setup and init watchdog
    var wd: zga.ZGA_WATCHDOG = .{};
    defer wd.deinit();
    try zga._inotify.watchdogInit(&wd.platform_vars, alloc);

    // Add watch to trigger events (create and delete)
    try zga._inotify.watchdogAdd(&wd.platform_vars, "../../test", zga.ZGA_DELETE | zga.ZGA_CREATE);

    // execute max number of events before reading --> cause an overflow err
    for (0..14) |_| {
        // Create file and then delete it in "./test" directory --> should be seen and captured by watcher
        var cwd: std.fs.Dir = std.fs.cwd();
        const p_file = try cwd.createFile("../../test/wd_read_test_file_987654321.txt", .{});
        defer p_file.close();
        try cwd.deleteFile("../../test/wd_read_test_file_987654321.txt");
    }

    // Call watchdogRead to process events
    var event_buf: [zga.SIZE_EVENT_QUEUE]zga.ZGA_EVENT = undefined;
    var error_buf: [zga.SIZE_ERROR_QUEUE]anyerror = undefined;
    var event_queue = std.fifo.LinearFifo(zga.ZGA_EVENT, .Slice).init(&event_buf); // init the LinearFIFO 
    var error_queue = std.fifo.LinearFifo(anyerror, .Slice).init(&error_buf); // init the LinearFIFO 
    try zga._inotify.watchdogRead(&wd.platform_vars, zga.ZGA_DELETE | zga.ZGA_CREATE, &event_queue, &error_queue);

    for (0..14) |_| {
        const val = event_queue.readItem();
        if (val) |v| {
            std.debug.print("{s}\n", .{v.name_buf});
        }
    }


}