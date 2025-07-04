/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const zga = @import("zga.zig");
const linux = std.os.linux;

///////////////////////////////
// MAGIC NUMBER DECLARATIONS //
///////////////////////////////

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
    fd: usize = 0,
    opt_hm_pathwatch: ?std.AutoHashMap([]const u8, usize) = null, // map watchdog fds to paths (also used to track num of open watchdogs)
};

//////////////////////////////////
// PUBLIC FUNCTION DECLARATIONS //
//////////////////////////////////

pub fn watchdogInit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init == true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd != 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_pathwatch != null) return error.WATCHDOG_HASHMAP_ALREADY_INIT;

    // init inotify file desc
    const fd: usize = std.os.linux.inotify_init1(IN_NONBLOCK | IN_CLOEXEC); // def init
    if (fd < 0) return error.FAILED_TO_INIT_INOTIFY_FD; // if fd is negative, an err occurred

    // init hashmap for storing watchdog ptrs
    const hm = std.AutoHashMap([]const u8, usize).init(p_wd.alloc.?); // creating hashmap

    // if no errors have occurred --> set values now
    p_wd.platform_vars.fd = fd; // setting fd in global iNotify vars
    p_wd.platform_vars.opt_hm_pathwatch = hm; // assigning hashmap to 
}

pub fn watchdogAdd(p_wd: *zga.ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd == 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_pathwatch == null) return error.WATCHDOG_HASHMAP_ALREADY_INIT;
    
    const path_null_term: [:0]const u8 = path ++ "\x00"; // null-terminating parsed path (required for inotify funcs)
    const watch_desc: usize = linux.inotify_add_watch(p_wd.platform_vars.fd, path_null_term.ptr, flags);
    if (watch_desc < 0) return error.FAILED_TO_ADD_WATCHDOG_FILE;
    errdefer _ = linux.inotify_rm_watch(p_wd.platform_vars.fd, watch_desc); // remove watchdog if can't add it to hashmap
    try p_wd.platform_vars.opt_hm_pathwatch.?.put(path, watch_desc); // adding watchdog descriptor to the global hashmap
}

pub fn watchdogRemove(p_wd: *zga.ZGA_WATCHDOG, path: []const u8) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd == 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_pathwatch == null) return error.WATCHDOG_HASHMAP_ALREADY_INIT;

    // collecting the watchdog descriptor that is tied to the provided path and removing the watcher
    if (p_wd.platform_vars.opt_hm_pathwatch.?.get(path)) |wd_desc| {
        _ = linux.inotify_rm_watch(p_wd.platform_vars.fd, wd_desc); // remove watchdog if can't add it to hashmap
    }
}

pub fn watchdogPoll(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd == 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_pathwatch == null) return error.WATCHDOG_HASHMAP_ALREADY_INIT;



    // TO BE DONE



}

pub fn watchdogThreadedPoll(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd == 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_pathwatch == null) return error.WATCHDOG_HASHMAP_ALREADY_INIT;



    // TO BE DONE 





}

pub fn watchdogDeinit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd == 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_pathwatch == null) return error.WATCHDOG_HASHMAP_ALREADY_INIT;

    // iterate over each wd_desc and call watchdogRemove on it
    const hm_iterator = p_wd.platform_vars.opt_hm_pathwatch.?.iterator();
    

    



    // need to iterate over all and watchdogRemove() each (from hashmap)

    



    std.debug.print("{s}\n", .{ @typeName(@TypeOf(hm_iterator)) });


    



    // if no errors have occurred --> reset values now
    p_wd.platform_vars.fd = 0; 
    p_wd.platform_vars.opt_hm_pathwatch = null;
}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////
