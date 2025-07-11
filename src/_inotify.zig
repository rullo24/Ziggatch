/// @file _inotify.zig
///
/// Implements a Linux inotify-based filesystem watchdog for monitoring file and directory changes. 

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
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
/// - `alloc`: Allocator for internal values.
pub fn watchdogInit(p_platform_vars: *INOTIFY_VARS, alloc: std.mem.Allocator) !void {
    if (p_platform_vars.fd >= 0) return error.WATCHDOG_FILE_DESC_ALREADY_SET;
    if (p_platform_vars.opt_hm_path_to_wd != null) return error.PATH_TO_WATCHDOG_HASHMAP_ALREADY_INIT;
    if (p_platform_vars.opt_hm_wd_to_path != null) return error.WATCHDOG_TO_PATH_HASHMAP_ALREADY_INIT;

    // init inotify file desc
    const fd: i32 = try posix.inotify_init1(IN_CLOEXEC); // synchronous (blocking)
    errdefer std.posix.close(fd);

    // init hashmap for storing watchdog ptrs
    const path_to_wd_hm = std.StringHashMap(i32).init(alloc);
    errdefer path_to_wd_hm.deinit();
    const wd_to_path_hm = std.AutoHashMap(i32, []const u8).init(alloc);
    errdefer wd_to_path_hm.deinit();

    // if no errors have occurred --> set values now
    p_platform_vars.fd = fd; // setting fd in global iNotify vars
    p_platform_vars.opt_hm_path_to_wd = path_to_wd_hm;
    p_platform_vars.opt_hm_wd_to_path = wd_to_path_hm;
}

/// adds a directory or file path to the watchlist with specified event flags.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
/// - `path`: UTF-8 path to the directory or file to watch.
/// - `zga_flags`: Bitmask of ZGA event flags indicating which changes to monitor.
pub fn watchdogAdd(p_platform_vars: *INOTIFY_VARS, path: []const u8, zga_flags: u32) !void {
    if (p_platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;

    // checking if flags are valid
    const inotify_flags: u32 = ZGAToInotifyFlags(zga_flags);
    if (inotify_flags == 0x0) return error.NO_FLAGS_PARSED;

    // will err if there is already a path in the hashmap (already set)
    if (p_platform_vars.opt_hm_path_to_wd) |hm_path_to_wd| {
        if (hm_path_to_wd.contains(path) == true) return error.WATCHDOG_ALREADY_ADDED_FOR_PATH; 
    } else return error.WATCHDOG_TO_PATH_HASHMAP_NOT_INIT;

    // adding new watcher w/ flags (parsed)
    const watch_desc: i32 = try posix.inotify_add_watch(p_platform_vars.fd, path, inotify_flags);
    errdefer posix.inotify_rm_watch(p_platform_vars.fd, watch_desc); // remove watchdog if can't add it to hashmap
    if (watch_desc < 0) return error.FAILED_TO_ADD_WATCHDOG_FILE;

    // adding watchdog descriptor to the global hashmaps
    if (p_platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
        try p_hm_path_to_wd.put(path, watch_desc);
    } else return error.HM_PATH_TO_WD_NOT_INIT;
    if (p_platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| {
        try p_hm_wd_to_path.put(watch_desc, path);
    } else return error.HM_WD_TO_PATH_NOT_INIT;
}

/// removes a watched path from the watchlist.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
/// - `path`: UTF-8 path to remove from watching.
pub fn watchdogRemove(p_platform_vars: *INOTIFY_VARS, path: []const u8) !void {
    if (p_platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;

    // collecting the watchdog descriptor that is tied to the provided path and removing the watcher
    if (p_platform_vars.opt_hm_path_to_wd) |hm_path_to_wd| {
        if (hm_path_to_wd.get(path)) |wd_from_path| {
            posix.inotify_rm_watch(p_platform_vars.fd, wd_from_path); // remove watchdog if can't add it to hashmap
            if (p_platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| {
                const wd_rm_resp_wd: bool = p_hm_wd_to_path.remove(wd_from_path); // removing entry from hashmap
                if (wd_rm_resp_wd == false) return error.ATTEMPT_TO_REMOVE_WD_THAT_DOES_NOT_EXIST_IN_HASHMAP;
            } else return error.HM_WD_TO_PATH_NOT_INIT;

            if (p_platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
                const wd_rm_resp_path: bool = p_hm_path_to_wd.remove(path); // removing entry from hashmap
                if (wd_rm_resp_path == false) return error.ATTEMPT_TO_REMOVE_PATH_THAT_DOES_NOT_EXIST_IN_HASHMAP;
            }
        } else return error.HM_PATH_TO_WD_NOT_INIT;
    }
}

/// reads file change events and pushes them to the event queue.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
/// - `zga_flags`: Bitmask of ZGA event flags to filter which changes are captured (unused on Linux).
/// - `p_event_queue`: Pointer to the event queue used for storing file events from the watchdog
/// - `p_error_queue`: Pointer to the error queue used for storing error events from the watchdog
pub fn watchdogRead(p_platform_vars: *INOTIFY_VARS, zga_flags: u32, p_event_queue: *std.fifo.LinearFifo(zga.ZGA_EVENT, .Slice), p_error_queue: *std.fifo.LinearFifo(anyerror, .Slice)) !void {
    if (p_platform_vars.fd < 0) return error.WATCHDOG_FILE_DESC_NOT_SET;

    // NOTE: flags don't require checking as they are not used in Linux _inotify watchdogRead()

    // buf to hold read events (read will return all events since last call)
    var buf: [INOTIFY_READ_BUF_LEN]u8 = undefined; // u8 == byte --> matches with @sizeOf()

    // posix.read WILL block until data is available
    const len_read: usize = try posix.read(p_platform_vars.fd, buf[0..INOTIFY_READ_BUF_LEN]); 
    if (len_read == 0) return; // nothing read
    
    // iterating over all values in read buffer --> checking maps
    var i: usize = 0;
    while (i < len_read) { // iterating over all read inotify responses
        const p_curr_event: *linux.inotify_event = @alignCast(@ptrCast(buf[i..].ptr)); // cast bytes to aligned inotify_event ptr
        if ((p_curr_event.mask & IN_Q_OVERFLOW) != 0) { // occurs if the provided buffer is too small for the num of events or removed inotify event comes through
            try p_error_queue.writeItem(error.EVENT_READ_OVERFLOWED_SOME_EVENTS_LOST); // writing to err queue

        } else if ((p_curr_event.mask & IN_IGNORED) != 0) {
            // pass --> do nothing for ignored events

        } else {
            // adding the event to the global queue --> for processing in ZGA
            var zga_curr_event: zga.ZGA_EVENT = .{}; // def vals
            zga_curr_event.zga_flags = zga_flags; // --> zga_flags set by response on Linux version (in lines below)

            // set name in event --> based on type of file wd attached to
            if (std.os.linux.inotify_event.getName(p_curr_event)) |filename_c| { // if file event within directory (attached)
                const scope_temp_filename: []const u8 = std.mem.span(filename_c.ptr); // from null-term to []const u8

                // copying filename to event obj
                const max_filename_len: usize = @min(scope_temp_filename.len, zga_curr_event.name_buf.len);
                std.mem.copyForwards(u8, zga_curr_event.name_buf[0..max_filename_len], scope_temp_filename[0..max_filename_len]);
                zga_curr_event.name = zga_curr_event.name_buf[0..max_filename_len];
                zga_curr_event.zga_flags = inotifyToZGAFlags(p_curr_event.mask);

            } else { // if attached directly to file
                if (p_platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| {
                    const scope_temp_filename: []const u8 = p_hm_wd_to_path.get(p_curr_event.wd) orelse return error.COULD_NOT_FIND_EVENT_WD_IN_HM; // doesn't require allocated mem (stored on heap already --> free'd on deinit of watchdog or watchdogRemove)
                    
                    // copying filename to event obj
                    const max_filename_len: usize = @min(scope_temp_filename.len, zga_curr_event.name_buf.len);
                    std.mem.copyForwards(u8, zga_curr_event.name_buf[0..max_filename_len], scope_temp_filename[0..max_filename_len]);
                    zga_curr_event.name = zga_curr_event.name_buf[0..max_filename_len];
                    zga_curr_event.zga_flags = inotifyToZGAFlags(p_curr_event.mask);
                } else return error.HM_WD_TO_PATH_NOT_INIT;
            }

            // adding the event to the global queue 
            try p_event_queue.writeItem(zga_curr_event);
        }

        // incrementing ptr to next event
        i += @sizeOf(linux.inotify_event) + p_curr_event.*.len; 
    }
}

/// Returns a slice of filepath strings that are currently being watched. The returned slice must be deallocated externally after use.
/// 
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
/// - `alloc`: Allocator for internal values.
pub fn watchdogList(p_platform_vars: *INOTIFY_VARS, alloc: std.mem.Allocator) ![]const []const u8 {
    var wd_watchlist = std.ArrayList([]const u8).init(alloc);
    if (p_platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
        var hm_iterator = p_hm_path_to_wd.iterator();
        while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for deinit watchdogs via inotify
            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
            try wd_watchlist.append(curr_hm_val_str);
        }
    } else return error.HM_PATH_TO_WD_NOT_INIT;
    return wd_watchlist.toOwnedSlice(); // to be dealloc'd externally by user
}

/// cleans up all inotify-related watchdog resources.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
pub fn watchdogDeinit(p_platform_vars: *INOTIFY_VARS) void {
    // iterate over each wd_desc and call watchdogRemove on it + destroy the hashmap after doing so
    if (p_platform_vars.opt_hm_path_to_wd) |*p_hm_path_to_wd| {
        var hm_iterator = p_hm_path_to_wd.iterator();
        while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for deinit watchdogs via inotify
            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
            watchdogRemove(p_platform_vars, curr_hm_val_str) catch {}; // remove each hashmap key --> don't react to removal err to properly clean on end of func
        }

        // destroy the hashmap (path --> wd)
        p_hm_path_to_wd.deinit(); 

    } // don't return error if already null --> being set to null anyways

    // destroying data structures --> heap allocated (destroy the hashmap wd --> path)
    if (p_platform_vars.opt_hm_wd_to_path) |*p_hm_wd_to_path| p_hm_wd_to_path.deinit(); // don't return error if already null --> being set to null anyways

    // closing the file descriptor (POSIX) if available/open
    if (p_platform_vars.fd > -1) std.posix.close(p_platform_vars.fd); // closing file descriptor (if applicable)

    // if no errors have occurred --> reset values now
    p_platform_vars.fd = -1; 
    p_platform_vars.opt_hm_path_to_wd = null;
    p_platform_vars.opt_hm_wd_to_path = null;
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
    // Setup a fresh ZGA_WATCHDOG with alloc and all preconditions met
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
 
    // Call watchdogInit --> should succeed w/o errors
    try watchdogInit(&wd, alloc);

    // assert fd is set and hashmaps initialized
    try std.testing.expect(wd.platform_vars.fd >= 0);
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_wd != null);
    try std.testing.expect(wd.platform_vars.opt_hm_wd_to_path != null);
}

test "watchdogInit: Fails if file descriptor already set (platform_vars.fd >= 0)" {
    // Setup watchdog with platform_vars.fd >= 0
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    wd.platform_vars.fd = 2;

    // Call watchdogInit
    const result = watchdogInit(&wd, alloc);

    // Assert error.WATCHDOG_FILE_DESC_ALREADY_SET returned
    try std.testing.expectError(error.WATCHDOG_FILE_DESC_ALREADY_SET, result);
}

test "watchdogInit: Fails if path-to-watchdog hashmap already initialised (opt_hm_path_to_wd != null)" {
    // init hashmap
    const alloc: std.mem.Allocator = std.testing.allocator;
    const hm = std.StringHashMap(i32).init(alloc);

    // Setup watchdog with opt_hm_path_to_wd != null
    var wd: zga.ZGA_WATCHDOG = .{};
    wd.platform_vars.opt_hm_path_to_wd = hm; 

    // Call watchdogInit
    const result = watchdogInit(&wd, alloc);

    // Assert error.PATH_TO_WATCHDOG_HASHMAP_ALREADY_INIT returned
    try std.testing.expectError(error.PATH_TO_WATCHDOG_HASHMAP_ALREADY_INIT, result);
}

test "watchdogInit: Fails if watchdog-to-path hashmap already initialised (opt_hm_wd_to_path != null)" {
    // init hashmap
    const alloc: std.mem.Allocator = std.testing.allocator;
    const hm = std.AutoHashMap(i32, []const u8).init(alloc);

    // Setup watchdog with opt_hm_wd_to_path != null
    var wd: zga.ZGA_WATCHDOG = .{};
    wd.platform_vars.opt_hm_wd_to_path = hm;

    // Call watchdogInit
    const result = watchdogInit(&wd, alloc);

    // Assert error.WATCHDOG_TO_PATH_HASHMAP_ALREADY_INIT returned
    try std.testing.expectError(error.WATCHDOG_TO_PATH_HASHMAP_ALREADY_INIT, result);
}

test "watchdogInit: Validates that file descriptor is valid (> 0) after initialization" {
    // Setup a fresh watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};

    // Call watchdogInit
    try watchdogInit(&wd, alloc);

    // Assert that platform_vars.fd > 0 after init
    try std.testing.expect(wd.platform_vars.fd > 0);
}

test "watchdogInit: Idempotency: Re-calling deinit followed by init should succeed" {
    // Setup and init a fresh watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};

    // Call watchdog.deinit to reset its internal state
    wd.deinit();

    // Call watchdogInit again
    try watchdogInit(&wd, alloc);
}

// test "watchdogInit: Cleans up file descriptor if error occurs during 1st hashmap initialization" {
//     const alloc = std.testing.allocator;
//     var wd: zga.ZGA_WATCHDOG = .{};

//     // Use a failing allocator that fails immediately, so hashmap init fails on first alloc
//     const FailAllocType: type = fail.FailingAllocator(0, alloc);
//     const fail_alloc: std.mem.Allocator = FailAllocType{};

//     // Call watchdogInit with failing allocator
//     const err = watchdogInit(&wd, fail_alloc);

//     // Expect an error (likely OutOfMemory or allocation failure)
//     try std.testing.expectError(error.OutOfMemory, err);

//     // Assert that all values in struct are not init after fail
//     try std.testing.expect(wd.platform_vars.fd == -1);
//     try std.testing.expect(wd.platform_vars.opt_hm_path_to_wd == null);
//     try std.testing.expect(wd.platform_vars.opt_hm_wd_to_path == null);
// }


// test "watchdogInit: Cleans up file descriptor and 1st hashmap if error occurs during 2nd hashmap initialization" {
//     const alloc = std.testing.allocator;
//     var wd: zga.ZGA_WATCHDOG = .{};

//     // Use a failing allocator that fails immediately, so hashmap init fails on first alloc
//     const FailAllocType: type = fail.FailingAllocator(0, alloc);
//     const fail_alloc: std.mem.Allocator = FailAllocType{};

//     // Call watchdogInit with failing allocator
//     const err = watchdogInit(&wd, fail_alloc);

//     // Expect an error (likely OutOfMemory or allocation failure)
//     try std.testing.expectError(error.OutOfMemory, err);

//     // Assert that all values in struct are not init after fail
//     try std.testing.expect(wd.platform_vars.fd == -1);
//     try std.testing.expect(wd.platform_vars.opt_hm_path_to_wd == null);
//     try std.testing.expect(wd.platform_vars.opt_hm_wd_to_path == null);
// }

// watchdogAdd //

test "watchdogAdd: Fails if file descriptor not set (fd < 0)" {
    // Setup watchdog with has_been_init == true but fd == -1
    const alloc = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    try watchdogInit(&wd, alloc);
    wd.platform_vars.fd = -1;

    // Call watchdogAdd, expect error.WATCHDOG_FILE_DESC_NOT_SET
    const result = watchdogAdd(&wd, "./test/test_file.txt", zga.ZGA_CREATE); 
    try std.testing.expectError(error.WATCHDOG_FILE_DESC_NOT_SET, result);
}

test "watchdogAdd: Fails if path already added" {
    // Setup and init watchdog, add path to hashmap manually

    // Call watchdogAdd with the same path, expect error.WATCHDOG_ALREADY_ADDED_FOR_PATH
}

test "watchdogAdd: Fails if no flags parsed (inotify flags == 0)" {
    // Setup watchdog, has_been_init true, fd valid

    // Call watchdogAdd with zero flags, expect error.NO_FLAGS_PARSED
}

test "watchdogAdd: Successfully adds a path and watch descriptor" {
    // Setup watchdog fully initialized

    // Call watchdogAdd with valid path and flags

    // Verify hashmap entries exist for path and wd
}

test "watchdogAdd: Fails if inotify_add_watch returns error" {
    // Setup watchdog fully initialized with fd but simulate posix.inotify_add_watch failure

    // Call watchdogAdd, expect error.FAILED_TO_ADD_WATCHDOG_FILE
}

test "watchdogAdd: Correctly converts ZGA flags to inotify flags" {
    // Setup watchdog fully initialized

    // Call watchdogAdd with various zga_flags combinations

    // Assert internal inotify flags are set accordingly (mock or intercept)
}

test "watchdogAdd: Adds multiple different paths successfully" {
    // Setup watchdog fully initialized

    // Add several different paths

    // Assert all paths and watch descriptors present in hashmaps
}

test "watchdogAdd: Invalid file location parsed to add func" {
    // setup watchdog

    // run watchdogAdd with path to invalid loc

    // Assert error on result

}

// watchdogRemove //

test "watchdogRemove: Fails if watchdog not initialized" {
    // Setup watchdog with has_been_init == false

    // Call watchdogRemove, expect error.WATCHDOG_NOT_INIT
}

test "watchdogRemove: Fails if file descriptor not set" {
    // Setup watchdog with has_been_init == true but fd == -1

    // Call watchdogRemove, expect error.WATCHDOG_FILE_DESC_NOT_SET
}

test "watchdogRemove: Fails if path not in hashmap" {
    // Setup and initialize watchdog

    // Call watchdogRemove with a path not in hashmap, expect error.HM_DOES_NOT_CONTAIN_PATH_AS_KEY
}

test "watchdogRemove: Successfully removes a watched path" {
    // Setup and initialize watchdog

    // Add path to watchlist

    // Call watchdogRemove with added path

    // Verify hashmap entries for path and wd are removed
}

test "watchdogRemove: Fails if hashmaps are null" {
    // Setup watchdog with has_been_init == true but hashmaps null

    // Call watchdogRemove, expect error about hashmap not initialized
}

test "watchdogRemove: Fails if removal from hashmap returns false" {
    // Setup watchdog with hashmaps

    // Simulate hashmap remove returning false

    // Call watchdogRemove, expect error about removal failure
}

test "watchdogRemove: Handles invalid watch descriptor gracefully" {
    // Setup watchdog, add path with invalid watch descriptor

    // Call watchdogRemove, expect graceful removal or specific error
}

// watchdogRead //

test "watchdogRead: Fails if watchdog not initialized" {
    // Setup watchdog with has_been_init == false

    // Call watchdogRead, expect error.WATCHDOG_NOT_INIT
}

test "watchdogRead: Fails if file descriptor not set" {
    // Setup watchdog with has_been_init == true but fd == -1

    // Call watchdogRead, expect error.WATCHDOG_FILE_DESC_NOT_SET
}

test "watchdogRead: Successfully reads and processes events" {
    // Setup and initialize watchdog with real or mock fd

    // Add watch to trigger events

    // Trigger a filesystem event

    // Call watchdogRead to process events

    // Verify event queue contains expected events
}

test "watchdogRead: Adds EVENT_READ_OVERFLOWED_SOME_EVENTS_LOST on IN_Q_OVERFLOW" {
    // Setup watchdog with events including IN_Q_OVERFLOW

    // Call watchdogRead

    // Assert error event added to queue
}

test "watchdogRead: Ignores IN_IGNORED events" {
    // Setup watchdog with IN_IGNORED events

    // Call watchdogRead

    // Assert no events added for ignored masks
}


test "watchdogRead: No events processed if read returns zero" {
    // Setup watchdog

    // Simulate posix.read returns 0 bytes

    // Call watchdogRead and expect no events enqueued
}

test "watchdogRead: Returns error if wd_to_path hashmap is null during event processing" {
    // Setup watchdog with opt_hm_wd_to_path null

    // Simulate event without filename

    // Call watchdogRead, expect error.HM_WD_TO_PATH_NOT_INIT
}

// watchdogDeinit//

test "watchdogDeinit: Properly cleans up all resources" {
    // Setup and initialize watchdog

    // Add some paths/watch descriptors

    // Call watchdogDeinit

    // Assert fd reset to -1

    // Assert hashmaps are null
}

test "watchdogDeinit: No error if deinit called multiple times" {
    // Setup watchdog in a deinitialized state

    // Call watchdogDeinit multiple times to confirm idempotency
}

test "watchdogDeinit: Succeeds when called with null hashmaps" {
    // Setup watchdog with fd set but null hashmaps

    // Call watchdogDeinit, expect no error and cleanup fd
}

test "watchdogDeinit: Succeeds if file descriptor already closed or invalid" {
    // Setup watchdog with fd set to invalid value (-1 or closed)

    // Call watchdogDeinit, expect no error and reset state
}

////////////////////////////
// PRIVATE FUNCTION TESTS //
////////////////////////////
