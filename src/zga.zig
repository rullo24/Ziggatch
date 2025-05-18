// std imports
const std = @import("std");
const builtin = @import("builtin");
const win32 = std.os.windows;

// external imports
const tsq = @import("TSQ");

// local file imports
const _win = @import("_win.zig");
const _lini = @import("_linux_inotify.zig");

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
pub const ZGA_WATCHDOG = struct {
    const Self = @This();
    const b = selectBackend(); // selects backend from target compiled O/S

    has_been_init: bool = false,
    alloc: ?std.mem.Allocator = null,
    backend: b, // above func chooses target O/S file

    event_queue: tsq.createTSQ(ZGA_EVENT),
    error_queue: tsq.createTSQ(anyerror),

    fn init(self: *Self, alloc: std.mem.Allocator) !Self {
        if (self.has_been_init == true) return error.Already_Initialised;

        // setting field declarations
        self.alloc = alloc; // for freeing memory later
        
        // allocating thread-safe queue memory to heap --> to be freed on program close
        self.event_queue = tsq.createTSQ(ZGA_EVENT);
        self.event_queue.init(alloc, SIZE_EVENT_QUEUE);
        self.error_queue = tsq.createTSQ(anyerror);
        self.error_queue.init(alloc, SIZE_ERROR_QUEUE);

        // flag so that other methods cannot be run before initialisation
        self.has_been_init = true;
    }

    /// adding a directory to the obj watchlist
    fn add(self: *Self) void {
        // use std.meta.hasFn --> check if func available on target O/S
        _ = self;
    }

    /// removing a directory from obj watchlist
    fn remove(self: *Self) void {
        // use std.meta.hasFn --> check if func available on target O/S
        _ = self;
    }

    /// printing the obj watchlist
    fn watchList(self: *Self) void {
        // use std.meta.hasFn --> check if func available on target O/S
        _ = self;
    }

    fn close(self: *Self) !void {
        if (self.has_been_init != true) return error.ZGA_Object_Not_Initialised;

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

pub fn createWatchdog(alloc: std.mem.Allocator) !ZGA_WATCHDOG {
    var wd: ZGA_WATCHDOG = .{}; // create obj
    wd.init(alloc); // init using allocator that is passed --> heap allocation
    return wd;
}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////

// selects backend (methods to use) based on target architecture and O/S
fn selectBackend() type {
    switch(builtin.os.tag) {
        .windows => return _win,
        .linux => return _lini,
        else => @compileError("ZGA ERROR: Target O/S" ++ @tagName(builtin.os.tag) ++ "is not supported.\n"),
    }
}