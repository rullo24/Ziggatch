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

    const example_name: []const u8 = "/home/kali/Desktop/Ziggatch/zig-out/bin";
    try wd.add(example_name, 0x00000100);
    try wd.remove(example_name);
    try wd.add(example_name, 0x00000100);
    try wd.remove(example_name);
    try wd.add(example_name, 0x00000100);



    // UPDATE THE FLAGS SO THAT THERE ARE DEFAULT VALUES VIA ENUM OR SIMILAR
        // --> these should be converted to o/s specific flags or throw error if not available




    const one_ms_to_ns: comptime_int = 1 * std.time.ns_per_ms;
    while (true) {
        std.debug.print("IN READ LOOP\n", .{});
        try wd.read();
        std.debug.print("OUT READ LOOP\n", .{});

        std.time.sleep(one_ms_to_ns);
        std.debug.print("SLEPT\n", .{});

        if (try wd.event_queue.?.getSize() > 0) {
            const event: zga.ZGA_EVENT = wd.popEvent() catch continue; 
            std.debug.print("popped event\n", .{});
            std.debug.print("{s}\n", .{event.name});
        }
    }

    const ex_watchlist = try wd.watchlist();
    defer alloc.free(ex_watchlist);
    for (ex_watchlist) |path| {
        std.debug.print("{s}\n", .{path});
    }
}