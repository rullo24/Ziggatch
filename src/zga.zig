// std imports
const std = @import("std");
const builtin = @import("builtin");
const win32 = std.os.windows;

// external imports
const tsq = @import("TSQ");

// local file imports
const _win = @import("_win.zig");
const _inotify = @import("_inotify.zig");

///////////////////////////////
// MAGIC NUMBER DECLARATIONS //
///////////////////////////////

const SIZE_EVENT_QUEUE: usize = 1024;
const SIZE_ERROR_QUEUE: usize = 64;

////////////////////////////////
// PUBLIC STRUCT DECLARATIONS //
////////////////////////////////

// represents a change to filesystem
pub const ZGA_EVENT = struct {
    name: []const u8,
    op: u32,
    prev_name: []const u8,
};

// object used for concurrently capturing file changes
pub const ZGA_WATCHDOG: type = struct {
    has_been_init: bool = false,
    alloc: ?std.mem.Allocator = null,
    backend: selectBackend() = selectBackend(){},
    event_queue: ?tsq.createTSQ(ZGA_EVENT) = null,
    error_queue: ?tsq.createTSQ(anyerror) = null,

    fn init(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) !void {
        if (self.has_been_init == true) return error.ALREADY_INITIALISED;
        self.alloc = alloc; // for freeing memory later
        self.event_queue = try tsq.createTSQ(ZGA_EVENT).init(self.alloc.?, SIZE_EVENT_QUEUE);
        self.error_queue = try tsq.createTSQ(anyerror).init(self.alloc.?, SIZE_ERROR_QUEUE);
        self.has_been_init = true; // flag so that other methods cannot be run before initialisation
    }

    /// adding a directory to the obj watchlist
    fn add(self: *ZGA_WATCHDOG) !void {
        // use std.meta.hasfn --> check if func available on target o/s
        _ = self;
    }

    /// removing a directory from obj watchlist
    fn remove(self: *ZGA_WATCHDOG) !void {
        // use std.meta.hasfn --> check if func available on target o/s
        _ = self;
    }

    /// printing the obj watchlist
    fn watchlist(self: *ZGA_WATCHDOG) !void {
        // use std.meta.hasfn --> check if func available on target o/s
        _ = self;
    }

    fn close(self: *ZGA_WATCHDOG) !void {
        if (self.has_been_init != true) return error.zga_object_not_initialised;

        // removing heap memory for thread-safe queues
        self.event_queue.deinit();
        self.error_queue.deinit();
        
        // flipping flag back so that the struct can still exist but non-initialised
        self.alloc = null;
        self.has_been_init = false;
    }
};

//////////////////////////////////
// PUBLIC FUNCTION DECLARATIONS //
//////////////////////////////////

pub fn createWatchdog() !ZGA_WATCHDOG {
    const wd: ZGA_WATCHDOG = .{}; 
    return wd;
}

pub fn initWatchdog(p_wd: *const ZGA_WATCHDOG, alloc: std.mem.Allocator) !void {
    try @constCast(p_wd).*.init(alloc);
}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////

// selects backend (methods to use) based on target architecture and O/S
fn selectBackend() type {
    switch(builtin.target.os.tag) {
        .windows => return _win,
        .linux => return _inotify,
        else => @compileError("ZGA ERROR: Target O/S" ++ @tagName(builtin.target.os.tag) ++ "is not supported.\n"),
    }
}