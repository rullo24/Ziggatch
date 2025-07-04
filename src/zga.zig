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

const SIZE_EVENT_QUEUE: usize           = 1024;
const SIZE_ERROR_QUEUE: usize           = 1024;

pub const ZGA_ACCESSED: comptime_int        = 1 << 0;
pub const ZGA_MODIFIED: comptime_int        = 1 << 1;
pub const ZGA_ATTRIB: comptime_int          = 1 << 2;
pub const ZGA_CREATE: comptime_int          = 1 << 3;
pub const ZGA_DELETE: comptime_int          = 1 << 4;
pub const ZGA_MOVED: comptime_int           = 1 << 5;

////////////////////////////////
// PUBLIC STRUCT DECLARATIONS //
////////////////////////////////

// represents a change to filesystem
pub const ZGA_EVENT = struct {
    name_buf: [std.fs.MAX_NAME_BYTES]u8 = undefined, // holds the path
    name: []const u8 = "",
    zga_flags: u32 = 0x0,
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
        if (self.alloc) |l_alloc| {
            self.event_queue = try tsq.createTSQ(ZGA_EVENT).init(l_alloc, SIZE_EVENT_QUEUE);
            self.error_queue = try tsq.createTSQ(anyerror).init(l_alloc, SIZE_ERROR_QUEUE);
        } else return error.INVALID_ALLOCATOR;
        try zga_backend.watchdogInit(self); // initialise O/S-specific vars and buffers
        self.has_been_init = true; // flag so that other methods cannot be run before initialisation
    }

    /// adding a directory to the obj watchlist
    pub fn add(self: *ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
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

    pub fn read(self: *ZGA_WATCHDOG) !void {
        if (std.meta.hasFn(zga_backend, "watchdogRead") == false) return error.watchdogRead_FUNC_NOT_AVAIL_ON_OS; // check if func available on target o/s
            zga_backend.watchdogRead(self) catch |read_err| {
                if (read_err != error.WouldBlock) return read_err; // error.WouldBlock returned when no data is available (only return other errors)
            };
    }

    pub fn popEvent(self: *ZGA_WATCHDOG) !ZGA_EVENT {
        if (self.event_queue) |event_queue| {
            const pop_event: ZGA_EVENT = try event_queue.pop();
            return pop_event;
        } else return error.EVENT_QUEUE_NULL;
    }

    pub fn popError(self: *ZGA_WATCHDOG) !anyerror {
        if (self.error_queue) |err_queue| {
            const pop_err: ZGA_EVENT = try err_queue.pop();
            return pop_err;
        } else return error.ERROR_QUEUE_NULL;
    }

    pub fn watchlist(self: *ZGA_WATCHDOG) ![][]const u8 {
        if (self.has_been_init == false) return error.WD_HAS_NOT_BEEN_INIT; // return an error for a non-initialised array
        if (self.alloc) |l_alloc| {
            var wd_watchlist = std.ArrayList([]const u8).init(l_alloc);
            switch (zga_backend) {
                _inotify => {
                    if (self.platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
                        var hm_iterator = p_hm_path_to_wd.iterator();
                        while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for deinit watchdogs via inotify
                            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
                            try wd_watchlist.append(curr_hm_val_str);
                        }
                    }
                }, 
                _win => {


                    // TBD


                }, 
                else => @compileError("ERROR: invalid backend")
            }
        return wd_watchlist.toOwnedSlice(); // to be free'd externally
        } else return error.INVALID_ALLOCATOR;
    }

    pub fn close(self: *ZGA_WATCHDOG) !void {
        if (self.has_been_init == false) return error.ZGA_WATCHDOG_OBJ_NOT_INITIALISED;
        if (std.meta.hasFn(zga_backend, "watchdogDeinit")) { // check if func available on target o/s
            try zga_backend.watchdogDeinit(self);
        }

        if (self.event_queue) |*p_event_queue| {
            // cleaning queue --> freeing all allocated heap memory
            while (try p_event_queue.getSize() > 0) { 
                const curr_event: ZGA_EVENT = try p_event_queue.pop();
                if (self.alloc) |l_alloc| {
                    l_alloc.free(curr_event.name);
                } else return error.INVALID_ALLOCATOR;
            } 

            try p_event_queue.deinit(); // freeing memory for thread-safe queue
            self.event_queue = null; // avoid dangling ptrs
        } else return error.NO_EVENT_QUEUE_ON_CLOSE;

        if (self.error_queue) |*p_err_queue| {
            try p_err_queue.deinit(); // freeing memory for thread-safe queue
            self.error_queue = null; // avoid dangling ptrs
        } else return error.NO_ERROR_QUEUE_ON_CLOSE;

        self.alloc = null; // deinit allocator
        self.has_been_init = false; // flipping flag back so that the struct can still exist but non-initialised
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