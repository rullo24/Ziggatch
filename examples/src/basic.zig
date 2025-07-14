const std = @import("std");
const zga = @import("ZGA");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    var wd: zga.ZGA_WATCHDOG = .{};
    try wd.init(alloc);
    defer wd.deinit();

    // - Create temp directory for storing files
    var tmp_dir: std.testing.TmpDir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_dir_loc: []const u8 = "C:\\Personal\\Coding_Local\\05-zig\\07-Ziggatch\\.zig-cache\\tmp";
    std.debug.print("DIRECTORY: {s}\n", .{tmp_dir_loc});
    
    // - Add path watcher
    try wd.add(tmp_dir_loc, zga.ZGA_CREATE | zga.ZGA_MOVED | zga.ZGA_ACCESSED);

    // - Read events --> does not work like inotify version --> does not show previous events before call
    while (true) {
        try zga._win.watchdogRead(&wd.platform_vars, zga.ZGA_CREATE | zga.ZGA_MOVED | zga.ZGA_ACCESSED, &wd.event_queue, &wd.error_queue);

        const event_slice: []zga.ZGA_EVENT = try wd.drainEventsAlloc(alloc);
        defer alloc.free(event_slice);
        const error_slice: []anyerror = try wd.drainErrorsAlloc(alloc);
        defer alloc.free(error_slice);

        for (event_slice) |event| {
            std.debug.print("EVENT: {s} | {d}\n", .{event.name_buf[0..event.name_len], event.zga_flags});
        }
        
        // // Creating files to check against watchdogRead
        // const file_creation_path: []const u8 = try std.fmt.allocPrint(alloc, "{s}/threaded_temp_file.txt", .{tmp_dir_loc});
        // defer alloc.free(file_creation_path);
        // var cwd = std.fs.cwd();
        // const file = try cwd.createFile(file_creation_path, .{});
        // file.close();
        // _ = try cwd.deleteFile(file_creation_path);
    }
}