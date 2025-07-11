/// @file zga_watchdog.zig
///
/// Cross-platform filesystem watcher for Windows and Linux.

/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const builtin = @import("builtin");
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

/////////////////////////////////
// LOCAL FILE GLOBAL VARIABLES //
/////////////////////////////////

var event_buf: [SIZE_EVENT_QUEUE]ZGA_EVENT = undefined;
var error_buf: [SIZE_ERROR_QUEUE]anyerror = undefined;

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
    platform_vars: selectPlatformVars() = selectPlatformVars(){},
    event_queue: std.fifo.LinearFifo(ZGA_EVENT, .Slice) = undefined,
    error_queue: std.fifo.LinearFifo(anyerror, .Slice) = undefined,

    // defining mutex vars for thread-safe execution
    has_been_init_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    platform_vars_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    event_queue_mutex: std.Thread.Mutex = std.Thread.Mutex{},
    error_queue_mutex: std.Thread.Mutex = std.Thread.Mutex{},

    /// Inits the ZGA_WATCHDOG object and allocates resources. Must be called before using other watchdog functions.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `alloc`: Allocator used for internal allocations.
    pub fn init(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();

        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();

        if (self.has_been_init == true) return error.ZGA_WATCHDOG_OBJ_ALREADY_INITIALISED;
        self.event_queue = std.fifo.LinearFifo(ZGA_EVENT, .Slice).init(&event_buf); // init the LinearFIFO 
        self.error_queue = std.fifo.LinearFifo(anyerror, .Slice).init(&error_buf); // init the LinearFIFO 

        // initialise O/S-specific vars and buffers
        if (std.meta.hasFn(zga_backend, "watchdogInit") == true) { // check if func available on target o/s
            try zga_backend.watchdogInit(self, alloc); // run O/S-specific func
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND; 

        // flip flag so that other methods can now be run
        self.has_been_init = true; 
    }

    /// Adds a path (file or directory) to the watchlist with specified event flags.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `path`: UTF-8 path to watch.
    /// - `flags`: Bitmask of event flags indicating which changes to monitor.
    pub fn add(self: *ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        if (std.meta.hasFn(zga_backend, "watchdogAdd")) { // check if func available on target o/s
            try zga_backend.watchdogAdd(self, path, flags); // running O/S-specific func
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
    }

    /// Removes a path from the watchlist.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `path`: UTF-8 path to remove from watching.
    pub fn remove(self: *ZGA_WATCHDOG, path: []const u8) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();

        // check if func available on target O/S
        if (std.meta.hasFn(zga_backend, "watchdogRemove")) { 
            try zga_backend.watchdogRemove(self, path);
        } else return error.ADD_FUNC_DNE_IN_ZGA_BACKEND;
    }

    /// Reads file change events and pushes them to the event queue. This must be run continuously to scan for updates.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `flags`: Bitmask of event flags to filter which changes are captured (may be unused depending on backend).
    pub fn read(self: *ZGA_WATCHDOG, flags: u32) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        // check if func available on target O/S
        if (std.meta.hasFn(zga_backend, "watchdogRead") == true) {
            zga_backend.watchdogRead(self, flags) catch |read_err| {
                if (read_err != error.WouldBlock) return read_err; // error.WouldBlock returned when no data is available (only return other errors)
            };
        } else return error.watchdogRead_FUNC_NOT_AVAIL_ON_OS; 
    }

    /// Pops a single event from the event queue. Returns null if there aren't any available queue values
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    pub fn popEvent(self: *ZGA_WATCHDOG) !ZGA_EVENT {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();

        // capturing 1x ZGA_EVENT item from the queue
        return self.event_queue.readItem() orelse error.EMPTY_EVENT_QUEUE;
    }

    /// Pops all available events from the event queue and returns them as an allocated slice (user to dealloc external slice).
    /// 
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `alloc`: Allocator used to allocate the output slice.
    pub fn drainEventsAlloc(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) ![]ZGA_EVENT {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();

        // checking if events queue is empty --> return error
        if (self.event_queue.readableLength() == 0) return error.EMPTY_EVENT_QUEUE;

        // init ArrayList to store the events --> to be dealloc'd externally
        var l_arrlist = std.ArrayList(ZGA_EVENT).init(alloc);

        // cycle over each item in the events queue --> popping each
        while (self.event_queue.readItem()) |curr_item| {
            l_arrlist.append(curr_item); // pop each item and store in Arraylist
        }

        return l_arrlist.toOwnedSlice(); // to be dealloc'd externally
    }

    /// Processes and removes all available events from the event queue using a user-provided function pointer.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `p_func`: Function pointer to a callback that processes each event. Must accept a `*ZGA_EVENT` and a user-provided argument.
    /// - `p_args`: Opaque pointer passed to `p_func` along with each event.
    pub fn processAndClearEvents(self: *ZGA_WATCHDOG, p_func: *const fn (*anyopaque) void, p_args: *const anyopaque) !void {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();

        // checking if events queue is empty --> return error
        if (self.event_queue.readableLength() == 0) return error.EMPTY_EVENT_QUEUE;

        // cycle over each item in the events queue --> popping each
        while (self.event_queue.readItem()) |*p_curr_item| {
            p_func(p_curr_item, p_args); // call user callback with current event and user-parsed args
        }
    }

    /// Pops a single event from the error queue. Returns null if there aren't any available queue values
    /// 
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    pub fn popError(self: *ZGA_WATCHDOG) !anyerror {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        return self.error_queue.readItem() orelse error.EMPTY_ERROR_QUEUE;
    }

    /// Pops all available errors from the error queue and returns them as an allocated slice.
    /// 
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `alloc`: Allocator used to allocate the output slice.
    pub fn drainErrorsAlloc(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) ![]anyerror {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;
        
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        // checking if error queue is empty --> return error
        if (self.error_queue.readableLength() == 0) return error.EMPTY_ERROR_QUEUE;

        // init ArrayList to store the errors --> to be dealloc'd externally
        var l_arrlist = std.ArrayList(anyerror).init(alloc);

        // cycle over each item in the error queue --> popping each
        while (self.error_queue.readItem()) |curr_item| {
            l_arrlist.append(curr_item); // pop each item and store in Arraylist
        }

        return l_arrlist.toOwnedSlice(); // to be dealloc'd externally
    }

    
    /// Processes and removes all errors from the error queue using a user-provided function.
    /// 
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `p_func`: Callback function applied to each error. Must accept a `*anyerror` and a user-provided argument.
    /// - `p_args`: Opaque pointer passed to `p_func` along with each error.
    pub fn processAndClearErrors(self: *ZGA_WATCHDOG, p_func: *const fn (*anyopaque) void, p_args: *const anyopaque) !void { 
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();

        // checking if error queue is empty --> return error
        if (self.error_queue.readableLength() == 0) return error.EMPTY_ERROR_QUEUE;

        // cycle over each item in the error queue --> popping each
        while (self.error_queue.readItem()) |*p_curr_item| {
            p_func(p_curr_item, p_args); // call user callback with current event and user-parsed args
        }
    }

    /// Returns an allocated list (as a slice) of all currently watched paths. Slice of paths must be freed by the caller.
    ///
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    /// - `alloc`: Allocator used to allocate the returned list.
    pub fn getWatchlistAlloc(self: *ZGA_WATCHDOG, alloc: std.mem.Allocator) ![][]const u8 {
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
        if (self.has_been_init == false) return error.WATCHDOG_NOT_INIT;

        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        self.alloc_mutex.lock();
        defer self.alloc_mutex.unlock();

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

    /// Cleans up all watchdog resources, freeing internal allocations. After this call, the object must be re-initialised before reuse.
    /// 
    /// PARAMS:
    /// - `self`: The acting watchdog instance.
    pub fn deinit(self: *ZGA_WATCHDOG) void {
        // don't check has_been_init --> should safely deinit each if available anyways
        // if (self.has_been_init == false) return error.WD_HAS_NOT_BEEN_INIT; // return an error for a non-initialised array

        // deinit the objs associated inside of the O/S-specific files
        self.platform_vars_mutex.lock();
        defer self.platform_vars_mutex.unlock();
        if (std.meta.hasFn(zga_backend, "watchdogDeinit")) { // check if func available on target o/s
            zga_backend.watchdogDeinit(self);
        }

        // iterating over event queue --> cleaning and clearing
        self.event_queue_mutex.lock();
        defer self.event_queue_mutex.unlock();
        self.event_queue.deinit(); // only does anything if set to .Dynamic mode --> leave here for readability

        // iterating over error queue --> cleaning and clearing
        self.error_queue_mutex.lock();
        defer self.error_queue_mutex.unlock();
        self.error_queue.deinit(); // only does anything if set to .Dynamic mode --> leave here for readability

        // restating the object as uninitialised
        self.has_been_init_mutex.lock();
        defer self.has_been_init_mutex.unlock();
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