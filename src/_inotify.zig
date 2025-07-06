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

/// inits the inotify-based watchdog resources and internal structures.
/// Must be called before using other watchdog functions.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
pub fn watchdogInit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init == true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.fd >= 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd != null) return error.PATH_TO_WATCHDOG_HASHMAP_ALREADY_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path != null) return error.WATCHDOG_TO_PATH_HASHMAP_ALREADY_INIT;

    // init hashmap for storing watchdog ptrs
    if (p_wd.alloc) |l_alloc| {
        // init inotify file desc
        const fd: i32 = try posix.inotify_init1(IN_CLOEXEC); // synchronous (blocking)
        errdefer std.posix.close(fd);

        const path_to_wd_hm = std.StringHashMap(i32).init(l_alloc);
        errdefer path_to_wd_hm.deinit();
        const wd_to_path_hm = std.AutoHashMap(i32, []const u8).init(l_alloc);
        errdefer wd_to_path_hm.deinit();

        // if no errors have occurred --> set values now
        p_wd.platform_vars.fd = fd; // setting fd in global iNotify vars
        p_wd.platform_vars.opt_hm_path_to_wd = path_to_wd_hm;
        p_wd.platform_vars.opt_hm_wd_to_path = wd_to_path_hm;
    }
}

/// adds a directory or file path to the watchlist with specified event flags.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
/// - `path`: UTF-8 path to the directory or file to watch.
/// - `zga_flags`: Bitmask of ZGA event flags indicating which changes to monitor.
pub fn watchdogAdd(p_wd: *zga.ZGA_WATCHDOG, path: []const u8, zga_flags: u32) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // will err if there is already a path in the hashmap (already set)
    if (p_wd.platform_vars.opt_hm_path_to_wd.?.contains(path) == true) return error.WATCHDOG_ALREADY_ADDED_FOR_PATH; 

    // adding new watcher w/ flags (parsed)
    const inotify_flags: u32 = ZGAToInotifyFlags(zga_flags);
    if (inotify_flags == 0x0) return error.NO_FLAGS_PARSED;
    const watch_desc: i32 = try posix.inotify_add_watch(p_wd.platform_vars.fd, path, inotify_flags);
    errdefer posix.inotify_rm_watch(p_wd.platform_vars.fd, watch_desc); // remove watchdog if can't add it to hashmap
    if (watch_desc < 0) return error.FAILED_TO_ADD_WATCHDOG_FILE;

    // adding watchdog descriptor to the global hashmaps
    if (p_wd.platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| try p_hm_path_to_wd.put(path, watch_desc);
    if (p_wd.platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| try p_hm_wd_to_path.put(watch_desc, path);
}

/// removes a watched path from the watchlist.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
/// - `path`: UTF-8 path to remove from watching.
pub fn watchdogRemove(p_wd: *zga.ZGA_WATCHDOG, path: []const u8) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // collecting the watchdog descriptor that is tied to the provided path and removing the watcher
    if (p_wd.platform_vars.opt_hm_path_to_wd.?.get(path)) |wd_from_path| {
        posix.inotify_rm_watch(p_wd.platform_vars.fd, wd_from_path); // remove watchdog if can't add it to hashmap
        if (p_wd.platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| {
            const wd_rm_resp_wd: bool = p_hm_wd_to_path.remove(wd_from_path); // removing entry from hashmap
            if (wd_rm_resp_wd == false) return error.ATTEMPT_TO_REMOVE_WD_THAT_DOES_NOT_EXIST_IN_HASHMAP;
        }

        if (p_wd.platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
            const wd_rm_resp_path: bool = p_hm_path_to_wd.remove(path); // removing entry from hashmap
            if (wd_rm_resp_path == false) return error.ATTEMPT_TO_REMOVE_PATH_THAT_DOES_NOT_EXIST_IN_HASHMAP;
        }
    } else return error.HM_DOES_NOT_CONTAIN_PATH_AS_KEY;
}

/// reads file change events and pushes them to the event queue.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
/// - `zga_flags`: Bitmask of ZGA event flags to filter which changes are captured (unused on Linux).
pub fn watchdogRead(p_wd: *zga.ZGA_WATCHDOG, zga_flags: u32) !void {
    _ = zga_flags; // unused in Linux version

    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;
    if (p_wd.platform_vars.opt_hm_path_to_wd == null) return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;
    if (p_wd.platform_vars.opt_hm_wd_to_path == null) return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // buf to hold read events (read will return all events since last call)
    var buf: [INOTIFY_READ_BUF_LEN]u8 = undefined; // u8 == byte --> matches with @sizeOf()

    // posix.read WILL block until data is available
    const len_read: usize = try posix.read(p_wd.platform_vars.fd, buf[0..INOTIFY_READ_BUF_LEN]); 
    if (len_read == 0) return; // nothing read
    
    // iterating over all values in read buffer --> checking maps
    var i: usize = 0;
    while (i < len_read) { // iterating over all read inotify responses
        const p_curr_event: *linux.inotify_event = @alignCast(@ptrCast(buf[i..].ptr)); // cast bytes to aligned inotify_event ptr
        if ((p_curr_event.mask & IN_Q_OVERFLOW) != 0) { // occurs if the provided buffer is too small for the num of events or removed inotify event comes through
            if (p_wd.error_queue) |*p_err_queue| try p_err_queue.push(error.EVENT_READ_OVERFLOWED_SOME_EVENTS_LOST);
        } else if ((p_curr_event.mask & IN_IGNORED) != 0) {
            // pass --> do nothing for ignored events
        } else {
            // adding the event to the global queue --> for processing in ZGA
            var zga_curr_event: zga.ZGA_EVENT = .{}; // def vals

            // set name in event --> based on type of file wd attached to
            if (std.os.linux.inotify_event.getName(p_curr_event)) |filename_c| { // if file event within directory (attached)
                const scope_temp_filename: []const u8 = std.mem.span(filename_c.ptr); // from null-term to []const u8 --> required alloc'd mem?

                // copying filename to event obj
                const max_filename_len: usize = @min(scope_temp_filename.len, zga_curr_event.name_buf.len);
                std.mem.copyForwards(u8, zga_curr_event.name_buf[0..max_filename_len], scope_temp_filename[0..max_filename_len]);
                zga_curr_event.name = zga_curr_event.name_buf[0..max_filename_len];
                zga_curr_event.zga_flags = inotifyToZGAFlags(p_curr_event.mask);

            } else { // if attached directly to file
                if (p_wd.platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| {
                    const scope_temp_filename: []const u8 = p_hm_wd_to_path.get(p_curr_event.wd) orelse return error.COULD_NOT_FIND_EVENT_WD_IN_HM; // doesn't require allocated mem
                    
                    // copying filename to event obj
                    const max_filename_len: usize = @min(scope_temp_filename.len, zga_curr_event.name_buf.len);
                    std.mem.copyForwards(u8, zga_curr_event.name_buf[0..max_filename_len], scope_temp_filename[0..max_filename_len]);
                    zga_curr_event.name = zga_curr_event.name_buf[0..max_filename_len];
                    zga_curr_event.zga_flags = inotifyToZGAFlags(p_curr_event.mask);
                } else return error.HM_WD_TO_PATH_NOT_INIT;
            }

            // adding the event to the global queue --> user to interpret this data
            if (p_wd.event_queue) |*p_event_queue| {
                try p_event_queue.push(zga_curr_event); 
            }
        }

        // incrementing ptr to next event
        i += @sizeOf(linux.inotify_event) + p_curr_event.*.len; 
    }
}

/// cleans up all inotify-related watchdog resources.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
pub fn watchdogDeinit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init != true) return error.WATCHDOG_NOT_INIT;
    if (p_wd.platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;

    // iterate over each wd_desc and call watchdogRemove on it + destroy the hashmap after doing so
    if (p_wd.platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
        var hm_iterator = p_hm_path_to_wd.iterator();
        while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for deinit watchdogs via inotify
            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
            watchdogRemove(p_wd, curr_hm_val_str) catch {}; // remove each hashmap key --> don't react to removal err to properly clean on end of func
        }

        // destroy the hashmap (path --> wd)
        p_hm_path_to_wd.deinit(); 

    } else return error.PATH_TO_WATCHDOG_HASHMAP_NOT_INIT;

    // destorying data structures --> heap allocated
    if (p_wd.platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| {
        p_hm_wd_to_path.deinit(); // destroy the hashmap (wd --> path)
    } else return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // if no errors have occurred --> reset values now
    std.posix.close(p_wd.platform_vars.fd); // closing file descriptor
    p_wd.platform_vars.fd = -1; 
    p_wd.platform_vars.opt_hm_path_to_wd = null;
    p_wd.platform_vars.opt_hm_wd_to_path = null;
}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////

/// converts an inotify mask to a cross-platform ZGA event flag bitmask.
///
/// PARAMS:
/// - `inotify_mask`: The inotify event mask.
fn inotifyToZGAFlags(inotify_mask: u32) u32 {
    var zga_mask: u32 = 0x0;

    if ((inotify_mask & IN_ACCESS) != 0) zga_mask |= zga.ZGA_ACCESSED;
    if ((inotify_mask & IN_MODIFY) != 0) zga_mask |= zga.ZGA_MODIFIED;
    if ((inotify_mask & IN_ATTRIB) != 0) zga_mask |= zga.ZGA_ATTRIB;
    if ((inotify_mask & IN_CREATE) != 0) zga_mask |= zga.ZGA_CREATE;
    if ((inotify_mask & IN_DELETE) != 0) zga_mask |= zga.ZGA_DELETE;
    if ((inotify_mask & IN_DELETE_SELF) != 0) zga_mask |= zga.ZGA_DELETE;
    if ((inotify_mask & IN_MOVED_FROM) != 0) zga_mask |= zga.ZGA_MOVED;
    if ((inotify_mask & IN_MOVED_TO) != 0) zga_mask |= zga.ZGA_MOVED;
    if ((inotify_mask & IN_MOVE_SELF) != 0) zga_mask |= zga.ZGA_MOVED;

    return zga_mask;
}

/// converts a ZGA event flag bitmask to an inotify event mask.
///
/// PARAMS:
/// - `zga_mask`: The ZGA event flag bitmask.
fn ZGAToInotifyFlags(zga_mask: u32) u32 {
    var inotify_mask: u32 = 0x0;

    if ((zga_mask & zga.ZGA_ACCESSED) != 0) inotify_mask |= IN_ACCESS;
    if ((zga_mask & zga.ZGA_MODIFIED) != 0) inotify_mask |= IN_MODIFY;
    if ((zga_mask & zga.ZGA_ATTRIB) != 0) inotify_mask |= IN_ATTRIB;
    if ((zga_mask & zga.ZGA_CREATE) != 0) inotify_mask |= IN_CREATE;
    if ((zga_mask & zga.ZGA_DELETE) != 0) inotify_mask |= IN_DELETE;
    if ((zga_mask & zga.ZGA_DELETE) != 0) inotify_mask |= IN_DELETE_SELF;
    if ((zga_mask & zga.ZGA_MOVED) != 0) inotify_mask |= IN_MOVED_FROM;
    if ((zga_mask & zga.ZGA_MOVED) != 0) inotify_mask |= IN_MOVED_TO;
    if ((zga_mask & zga.ZGA_MOVED) != 0) inotify_mask |= IN_MOVE_SELF;

    return inotify_mask;
}

///////////////////////////
// PUBLIC FUNCTION TESTS //
///////////////////////////

// watchdogInit //

test "watchdogInit: Successfully initializes watchdog when all preconditions are met" {
    // 1. Setup a fresh ZGA_WATCHDOG with alloc and all preconditions met
    var test_wd: zga.ZGA_WATCHDOG = .{};
    test_wd.alloc = std.heap.page_allocator;
    test_wd.has_been_init = false;
    test_wd.platform_vars.fd = -1;
    test_wd.platform_vars.opt_hm_path_to_wd = null;
    test_wd.platform_vars.opt_hm_wd_to_path = null;
 
    // 2. Call watchdogInit --> should succeed w/o errors
    try watchdogInit(&test_wd);

    // 3. assert fd is set and hashmaps initialized
    try std.testing.expect(test_wd.platform_vars.fd >= 0);
    try std.testing.expect(test_wd.platform_vars.opt_hm_path_to_wd != null);
    try std.testing.expect(test_wd.platform_vars.opt_hm_wd_to_path != null);

    // THIS SHOULD BE FORCING A FAIL BUT IT IS NOT USING "zig build tests"
    try std.testing.expect(test_wd.platform_vars.opt_hm_wd_to_path == null);



}

test "watchdogInit: Fails if watchdog already initialized (has_been_init == true)" {
    // Setup watchdog with has_been_init = true
    // Call watchdogInit
    // Assert error.WATCHDOG_ALREADY_INIT returned
}

test "watchdogInit: Fails if file descriptor already set (platform_vars.fd >= 0)" {
    // Setup watchdog with platform_vars.fd >= 0
    // Call watchdogInit
    // Assert error.WATCHDOG_FILE_DESC_ALREADY_SET returned
}

test "watchdogInit: Fails if path-to-watchdog hashmap already initialized (opt_hm_path_to_wd != null)" {
    // Setup watchdog with opt_hm_path_to_wd != null
    // Call watchdogInit
    // Assert error.PATH_TO_WATCHDOG_HASHMAP_ALREADY_INIT returned
}

test "watchdogInit: Fails if watchdog-to-path hashmap already initialized (opt_hm_wd_to_path != null)" {
    // Setup watchdog with opt_hm_wd_to_path != null
    // Call watchdogInit
    // Assert error.WATCHDOG_TO_PATH_HASHMAP_ALREADY_INIT returned
}

test "watchdogInit: Fails if allocator is null" {
    // Setup watchdog with alloc = null
    // Call watchdogInit
    // Assert appropriate error returned or behavior (depending on code)
}

test "watchdogInit: Cleans up file descriptor if error occurs during hashmap initialization" {
    // This might require mocking or instrumentation
    // Simulate an error during hashmap init or adding watchers
    // Ensure fd is closed on error
}

test "watchdogInit: Validates that file descriptor is valid (> 0) after initialization" {
    // Setup a fresh watchdog and call watchdogInit
    // Assert that platform_vars.fd > 0 after init
}

// watchdogAdd //


// watchdogRemove //


// watchdogRead //


// watchdogDeinit//

