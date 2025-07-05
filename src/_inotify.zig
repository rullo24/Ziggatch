/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const zga = @import("zga.zig");
const linux = std.os.linux;
const posix = std.posix;

///////////////////////////////
// MAGIC NUMBER DECLARATIONS //
///////////////////////////////

const MAX_NUM_EVENTS_PER_READ: comptime_int = 1024;
const INOTIFY_EVENT_SIZE_W_STR: comptime_int = @sizeOf(linux.inotify_event) + posix.NAME_MAX;
const INOTIFY_READ_BUF_LEN = MAX_NUM_EVENTS_PER_READ * INOTIFY_EVENT_SIZE_W_STR;

pub const IN_Q_OVERFLOW: comptime_int = 0x00004000; // signals that the inotify event queue has overflowed 
pub const IN_IGNORED: comptime_int = 0x00008000; // indicates that the watch was removed previously

pub const IN_NONBLOCK: comptime_int = 0x00000800;   // Non-blocking mode for inotify fd
pub const IN_CLOEXEC: comptime_int  = 0x00080000;   // Close-on-exec for inotify fd

pub const IN_ACCESS: comptime_int        = 0x00000001;  // File was accessed
pub const IN_MODIFY: comptime_int        = 0x00000002;  // File was modified
pub const IN_ATTRIB: comptime_int        = 0x00000004;  // Metadata changed (e.g. permissions)
pub const IN_CLOSE_WRITE: comptime_int   = 0x00000008;  // Writable file was closed
pub const IN_CLOSE_NOWRITE: comptime_int = 0x00000010;  // Unwritable file closed
pub const IN_OPEN: comptime_int          = 0x00000020;  // File was opened
pub const IN_MOVED_FROM: comptime_int    = 0x00000040;  // File moved out of watched directory
pub const IN_MOVED_TO: comptime_int      = 0x00000080;  // File moved into watched directory
pub const IN_CREATE: comptime_int        = 0x00000100;  // File/directory created
pub const IN_DELETE: comptime_int        = 0x00000200;  // File/directory deleted
pub const IN_DELETE_SELF: comptime_int   = 0x00000400;  // Watched file/directory itself deleted
pub const IN_MOVE_SELF: comptime_int     = 0x00000800;  // Watched file/directory itself moved

// Convenience flags (bitwise OR of base flags)
pub const IN_CLOSE: comptime_int = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
pub const IN_MOVE: comptime_int  = IN_MOVED_FROM | IN_MOVED_TO;
pub const IN_ALL_EVENTS: comptime_int = 0x00000FFF;

////////////////////////////////
// PUBLIC STRUCT DECLARATIONS //
////////////////////////////////

pub const INOTIFY_VARS = struct {
    fd: i32 = -1,
    opt_hm_path_to_wd: ?std.StringHashMap(i32) = null, // map paths to watchdog IDs
    opt_hm_wd_to_path: ?std.AutoHashMap(i32, []const u8) = null, // map watchdog IDs to paths
};

//////////////////////////////////
// PUBLIC FUNCTION DECLARATIONS //
//////////////////////////////////

pub fn watchdogInit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init == true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd >= 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd != null) return error.PATH_TO_WATCHDOG_HASHMAP_ALREADY_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path != null) return error.WATCHDOG_TO_PATH_HASHMAP_ALREADY_INIT;

    // init inotify file desc
    const fd: i32 = try posix.inotify_init1(IN_NONBLOCK | IN_CLOEXEC); // def init
    if (fd < 0) return error.FAILED_TO_INIT_INOTIFY_FD; // if fd is negative, an err occurred

    // init hashmap for storing watchdog ptrs
    const path_to_wd_hm = std.StringHashMap(i32).init(p_wd.alloc.?);
    const wd_to_path_hm = std.AutoHashMap(i32, []const u8).init(p_wd.alloc.?);

    // if no errors have occurred --> set values now
    p_wd.platform_vars.fd = fd; // setting fd in global iNotify vars
    p_wd.platform_vars.opt_hm_path_to_wd = path_to_wd_hm;
    p_wd.platform_vars.opt_hm_wd_to_path = wd_to_path_hm;
}

pub fn watchdogAdd(p_wd: *zga.ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    if (flags == 0x0) return error.INVALID_FLAGS_PARSED;
    if (p_wd.platform_vars.opt_hm_path_to_wd.?.contains(path) == true) return error.WATCHDOG_ALREADY_ADDED_FOR_PATH; // will err if there is already a path in the hashmap (already set)

    const watch_desc: i32 = try posix.inotify_add_watch(p_wd.platform_vars.fd, path, flags);
    errdefer posix.inotify_rm_watch(p_wd.platform_vars.fd, watch_desc); // remove watchdog if can't add it to hashmap
    if (watch_desc < 0) return error.FAILED_TO_ADD_WATCHDOG_FILE;

    // adding watchdog descriptor to the global hashmaps
    try p_wd.platform_vars.opt_hm_path_to_wd.?.put(path, watch_desc); 
    try p_wd.platform_vars.opt_hm_wd_to_path.?.put(watch_desc, path);
}

pub fn watchdogRemove(p_wd: *zga.ZGA_WATCHDOG, path: []const u8) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // collecting the watchdog descriptor that is tied to the provided path and removing the watcher
    if (p_wd.platform_vars.opt_hm_path_to_wd.?.get(path)) |wd_desc| {
        posix.inotify_rm_watch(p_wd.platform_vars.fd, wd_desc); // remove watchdog if can't add it to hashmap
    } else return error.HM_DOES_NOT_CONTAIN_PATH_AS_KEY;

    // removing the value from the storing hashmaps
    const wd_from_path: i32 = p_wd.platform_vars.opt_hm_path_to_wd.?.get(path) orelse return error.COULD_NOT_FIND_WD_FROM_PATH_IN_HM;
    const wd_rm_resp_wd: bool = p_wd.platform_vars.opt_hm_wd_to_path.?.remove(wd_from_path); // removing entry from hashmap
    if (wd_rm_resp_wd == false) return error.ATTEMPT_TO_REMOVE_WD_THAT_DOES_NOT_EXIST_IN_HASHMAP;

    const wd_rm_resp_path: bool = p_wd.platform_vars.opt_hm_path_to_wd.?.remove(path); // removing entry from hashmap
    if (wd_rm_resp_path == false) return error.ATTEMPT_TO_REMOVE_PATH_THAT_DOES_NOT_EXIST_IN_HASHMAP;
}

pub fn watchdogRead(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // reading from file descriptor the responds w/ events
    var buf: [INOTIFY_READ_BUF_LEN]u8 = undefined; // u8 == byte --> matches with @sizeOf()
    const len_read: usize = try posix.read(p_wd.platform_vars.fd, buf[0..INOTIFY_READ_BUF_LEN]);
    
    // iterating over all values in read buffer --> checking maps
    var i: usize = 0;
    while (i < len_read) { // iterating over all read inotify responses
        // const p_curr_event: *linux.inotify_event = @ptrCast(&buf[i]);
        const p_curr_event: *linux.inotify_event = @ptrCast(@alignCast(&buf[i]));
        if ((p_curr_event.mask & IN_Q_OVERFLOW) != 0 or (p_curr_event.mask & IN_IGNORED) != 0) { // occurs if the provided buffer is too small for the num of events or removed inotify event comes through
            try p_wd.error_queue.?.push(error.EVENT_QUEUE_OVERFLOWED_SOME_EVENTS_LOST);
            continue;
        } 

        // adding the event to the global queue --> for processing in ZGA
        var zga_curr_event: zga.ZGA_EVENT = .{}; // def vals

        // set name in event --> based on type of file wd attached to
        if (std.os.linux.inotify_event.getName(p_curr_event)) |filename_c| { // if file event within directory (attached)
            const scope_temp_filename: []const u8 = std.mem.span(filename_c.ptr); // from null-term to []const u8 --> required alloc'd mem?
            const heaped_filename: []const u8 = try p_wd.alloc.?.dupe(u8, scope_temp_filename); // allocating to heap for use after scope
            zga_curr_event.name = heaped_filename;
        } else { // if attached directly to file
            const scope_temp_filename: []const u8 = p_wd.platform_vars.opt_hm_wd_to_path.?.get(p_curr_event.wd) orelse return error.COULD_NOT_FIND_EVENT_WD_IN_HM; // doesn't require allocated mem
            const heaped_filename: []const u8 = try p_wd.alloc.?.dupe(u8, scope_temp_filename); // allocating to heap for use after scope
            zga_curr_event.name = heaped_filename;
        }

        // adding the event to the global queue --> user to interpret this data
        try p_wd.event_queue.?.push(zga_curr_event); 

        // incrementing ptr to next event
        i += @sizeOf(linux.inotify_event) + p_curr_event.*.len; 
    }
}

pub fn watchdogDeinit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // iterate over each wd_desc and call watchdogRemove on it
    var hm_iterator = p_wd.platform_vars.opt_hm_path_to_wd.?.iterator();
    while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for deinit watchdogs via inotify
        const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
        watchdogRemove(p_wd, curr_hm_val_str) catch {}; // remove each hashmap key --> don't react to removal err to properly clean on end of func
    }

    p_wd.platform_vars.opt_hm_path_to_wd.?.deinit(); // destroy the hashmap (path --> wd)
    p_wd.platform_vars.opt_hm_wd_to_path.?.deinit(); // destroy the hashmap (wd --> path)

    // if no errors have occurred --> reset values now
    p_wd.platform_vars.fd = -1; 
    p_wd.platform_vars.opt_hm_path_to_wd = null;
}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////
