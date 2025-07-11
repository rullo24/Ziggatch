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

pub const SIZE_EVENT_QUEUE: usize           = 1024;
pub const SIZE_ERROR_QUEUE: usize           = 1024;

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
    name_buf: [std.fs.max_path_bytes]u8 = undefined, // holds the path
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

    // defining mutex vars for thread-safe execution
    has_been_init_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    alloc_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    platform_vars_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    event_queue_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    error_queue_mutex: std.Thread.Mutex = std.Thread.Mutex{},

    /// inits the ZGA_WATCHDOG object and allocates resources.
    /// must be called before using other watchdog functions.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `alloc`: Allocator used for internal allocations.
    pub fn init(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == true) return error.ZGA_WATCHDOG_OBJ_ALREADY_INITIALISED;

        self.alloc_mutex.lock();
        defer self.alloc_mutex.unlock();
        self.alloc = alloc; // for freeing memory later

        if (self.alloc) |l_alloc| {
            self.event_queue_mutex.lock();
            defer self.event_queue_mutex.unlock();

            self.event_queue = try tsq.createTSQ(ZGA_EVENT).init(l_alloc, SIZE_EVENT_QUEUE);
            errdefer self.event_queue.?.deinit() catch {};

            self.error_queue_mutex.lock();
            defer self.error_queue_mutex.unlock();
            self.error_queue = try tsq.createTSQ(anyerror).init(l_alloc, SIZE_ERROR_QUEUE);
            errdefer self.error_queue.?.deinit() catch {};
        } else return error.INVALID_ALLOCATOR;
        
        // initialise O/S-specific vars and buffers
        if (std.meta.hasFn(zga_backend, "watchdogInit")) { // check if func available on target o/s
            try zga_backend.watchdogInit(self); 
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
        
        self.has_been_init = true; // flag so that other methods cannot be run before initialisation
    }

    /// adds a path (file or directory) to the watchlist with specified event flags.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `path`: UTF-8 path to watch.
    /// - `flags`: Bitmask of event flags indicating which changes to monitor.
    pub fn add(self: *ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();

        if (std.meta.hasFn(zga_backend, "watchdogAdd")) { // check if func available on target o/s
            try zga_backend.watchdogAdd(self, path, flags);
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
    }

    /// removes a path from the watchlist.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `path`: UTF-8 path to remove from watching.
    pub fn remove(self: *ZGA_WATCHDOG, path: []const u8) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();

        if (std.meta.hasFn(zga_backend, "watchdogRemove")) { // check if func available on target o/s
            try zga_backend.watchdogRemove(self, path);
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
    }

    /// reads file change events and pushes them to the event queue.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `flags`: Bitmask of event flags to filter which changes are captured (may be unused depending on backend).
    pub fn read(self: *ZGA_WATCHDOG, flags: u32) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        if (std.meta.hasFn(zga_backend, "watchdogRead") == false) return error.watchdogRead_FUNC_NOT_AVAIL_ON_OS; // check if func available on target o/s
            zga_backend.watchdogRead(self, flags) catch |read_err| {
                if (read_err != error.WouldBlock) return read_err; // error.WouldBlock returned when no data is available (only return other errors)
            };
    }

    /// pops a single event from the event queue.
    /// if the queue is empty, this function blocks until a pop value is available
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    pub fn popSingleEvent(self: *ZGA_WATCHDOG) !ZGA_EVENT {
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();

        if (self.event_queue) |*p_event_queue| {
            const pop_event: ZGA_EVENT = try p_event_queue.pop();
            return pop_event;
        } else return error.EVENT_QUEUE_NULL;
    }

    pub fn popAllEventsAlloc(self: *ZGA_WATCHDOG) ![]ZGA_EVENT {
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();

        // checking if event queue is available for use
        if (self.event_queue) |*p_event_queue| {

            // pop each item and store in Arraylist

            // return arraylist at end

        } else return error.EVENT_QUEUE_NULL;
    }

    pub fn cleanAndProcessEvents(self: *ZGA_WATCHDOG, p_func: *const fn (*anyopaque) void, p_args: *const anyopaque) !void {
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();

        // checking if event queue is available for use
        if (self.event_queue) |*p_event_queue| {

            // iterate over each item in queue (available)

            // for each item, run the function callback, taking the event as argument

        } else return error.EVENT_QUEUE_NULL;

    }

    /// pops a single event from the error queue.
    /// if the queue is empty, this function blocks until a pop value is available
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    pub fn popSingleError(self: *ZGA_WATCHDOG) !anyerror {
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        if (self.error_queue) |*p_err_queue| {
            const pop_err: ZGA_EVENT = try p_err_queue.pop();
            return pop_err;
        } else return error.ERROR_QUEUE_NULL;
    }

    /// returns an allocated list (as a slice) of all currently watched paths.
    /// slice of paths must be freed by the caller.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `alloc`: Allocator used to allocate the returned list.
    pub fn getWatchlistAlloc(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) ![][]const u8 {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        self.alloc_mutex.lock();
        defer self.alloc_mutex.unlock();

        if (self.has_been_init == false) return error.WD_HAS_NOT_BEEN_INIT; // return an error for a non-initialised array
        var wd_watchlist = std.ArrayList([]const u8).init(alloc);
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
                if (self.platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
                    var hm_iterator = p_hm_path_to_handle.iterator();
                    while (hm_iterator.next()) |hm_val| {
                        const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting path key from hashmap "Entry"
                        try wd_watchlist.append(curr_hm_val_str);
                    }
                }
            }, 
            else => @compileError("ERROR: invalid backend")
        }
        
        return wd_watchlist.toOwnedSlice(); // to be free'd externally
    }

    /// cleans up all watchdog resources, freeing internal allocations.
    /// after this call, the object must be re-initialised before reuse.
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    pub fn close(self: *ZGA_WATCHDOG) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        self.alloc_mutex.lock();
        defer self.alloc_mutex.unlock();
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        if (self.has_been_init == false) return error.ZGA_WATCHDOG_OBJ_NOT_INITIALISED;
        if (std.meta.hasFn(zga_backend, "watchdogDeinit")) { // check if func available on target o/s
            try zga_backend.watchdogDeinit(self);
        }

        if (self.event_queue) |*p_event_queue| {
            // cleaning queue --> freeing all allocated heap memory
            while (try p_event_queue.getSize() > 0) { 
                const curr_event: ZGA_EVENT = p_event_queue.pop() catch break;
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

/// selects the OS-specific backend implementation at compile-time.
/// PARAMS:
/// N/A
fn selectBackend() type {
    switch(builtin.target.os.tag) {
        .windows => return _win,
        .linux => return _inotify,
        else => @compileError("ZGA ERROR: Target O/S" ++ @tagName(builtin.target.os.tag) ++ "is not supported.\n"),
    }
}

/// selects the OS-specific platform variables struct type at compile-time.
/// PARAMS:
/// N/A
fn selectPlatformVars() type {
    switch(builtin.target.os.tag) {
        .windows => return _win.WIN32_VARS,
        .linux => return _inotify.INOTIFY_VARS,
        else => @compileError("ZGA ERROR: Target O/S" ++ @tagName(builtin.target.os.tag) ++ "is not supported.\n"),
    }
}