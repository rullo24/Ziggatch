/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const builtin = @import("builtin");
const tsq = @import("TSQ");
const _win = @import("_win.zig");
const _inotify = @import("_inotify.zig");
const zga_backend: type = selectBackend();

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
    platform_vars: selectPlatformVars() = selectPlatformVars(){},
    event_queue: ?tsq.createTSQ(ZGA_EVENT) = null,
    error_queue: ?tsq.createTSQ(anyerror) = null,

    pub fn init(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) !void {
        if (self.has_been_init == true) return error.ZGA_WATCHDOG_OBJ_ALREADY_INITIALISED;
        self.alloc = alloc; // for freeing memory later
        self.event_queue = try tsq.createTSQ(ZGA_EVENT).init(self.alloc.?, SIZE_EVENT_QUEUE);
        self.error_queue = try tsq.createTSQ(anyerror).init(self.alloc.?, SIZE_ERROR_QUEUE);
        try zga_backend.watchdogInit(self); // initialise O/S-specific vars and buffers
        self.has_been_init = true; // flag so that other methods cannot be run before initialisation
    }

    /// adding a directory to the obj watchlist
    pub fn add(self: *ZGA_WATCHDOG, path: []const u8) !void {
        const flags: comptime_int = 0x0; // flags to be added here       

        if (std.meta.hasFn(zga_backend, "watchdogAdd")) { // check if func available on target o/s
            try zga_backend.watchdogAdd(self, path, flags);
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
    }

    /// removing a directory from obj watchlist
    pub fn remove(self: *ZGA_WATCHDOG, path: []const u8) !void {
        if (std.meta.hasFn(zga_backend, "watchdogRemove")) { // check if func available on target o/s
            try zga_backend.watchdogRemove(self, path);
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
    }

    /// printing the obj watchlist
    pub fn watchlist(self: *ZGA_WATCHDOG) !void {
        _ = self;


        // TBD



    }

    pub fn blockingPoll(self: *ZGA_WATCHDOG) !void {
        

        _ = self;
        // TBD


    }

    pub fn close(self: *ZGA_WATCHDOG) !void {
        if (self.has_been_init == false) return error.ZGA_WATCHDOG_OBJ_NOT_INITIALISED;
        if (std.meta.hasFn(zga_backend, "watchdogDeinit")) { // check if func available on target o/s
            try zga_backend.watchdogDeinit(self);
        }

        if (self.event_queue != null) {
            try self.event_queue.?.deinit(); // freeing memory for thread-safe queue
            self.event_queue = null; // avoid dangling ptrs
        }
        if (self.error_queue != null) {
            try self.error_queue.?.deinit(); // freeing memory for thread-safe queue
            self.error_queue = null; // avoid dangling ptrs
        }
        self.alloc = null; // deinit allocator
        self.has_been_init = false; // flipping flag back so that the struct can still exist but non-initialised
    }

    pub fn startThreadedPoll(self: *ZGA_WATCHDOG) !void {
        

        _ = self;
        // TBD


    }

    pub fn stopThreadedPoll(self: *ZGA_WATCHDOG) !void {



        _ = self;
        // TBD



    }
};

//////////////////////////////////
// PUBLIC FUNCTION DECLARATIONS //
//////////////////////////////////


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

// creates struct to hold OS-specific variables at comptime
fn selectPlatformVars() type {
    switch(builtin.target.os.tag) {
        .windows => return _win.WIN32_VARS,
        .linux => return _inotify.INOTIFY_VARS,
        else => @compileError("ZGA ERROR: Target O/S" ++ @tagName(builtin.target.os.tag) ++ "is not supported.\n"),
    }
}