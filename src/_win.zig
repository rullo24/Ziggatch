/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const win32 = std.os.windows;
const zga = @import("zga.zig");

///////////////////////////////
// MAGIC NUMBER DECLARATIONS //
///////////////////////////////

const MAX_NUM_EVENTS_PER_READ: comptime_int = 1024;

const FILE_NOTIFY_CHANGE_FILE_NAME: comptime_int = 0x00000001; // notify when a file is renamed, created, or deleted in the directory or subtree
const FILE_NOTIFY_CHANGE_DIR_NAME: comptime_int = 0x00000002; // notify when a directory is created or deleted in the directory or subtree
const FILE_NOTIFY_CHANGE_ATTRIBUTES: comptime_int = 0x00000004; // notify when any file or directory attributes are changed (e.g., read-only, hidden)
const FILE_NOTIFY_CHANGE_SIZE: comptime_int = 0x00000008; // notify when a file's size is modified (detected when written to disk)
const FILE_NOTIFY_CHANGE_LAST_WRITE: comptime_int = 0x00000010; // notify when the last write timestamp of a file changes (after flushing cache)
const FILE_NOTIFY_CHANGE_LAST_ACCESS: comptime_int = 0x00000020; // notify when the last access timestamp of a file changes
const FILE_NOTIFY_CHANGE_CREATION: comptime_int = 0x00000040; // notify when the creation time of a file changes
const FILE_NOTIFY_CHANGE_SECURITY: comptime_int = 0x00000100; // notify when the security settings of a file or directory are modified

////////////////////////////////
// PUBLIC STRUCT DECLARATIONS //
////////////////////////////////

pub const WIN32_VARS = struct {
    opt_hm_path_to_handle: ?std.StringHashMap(win32.HANDLE) = null, // map paths to watchdog IDs
    opt_hm_handle_to_path: ?std.AutoHashMap(win32.HANDLE, []const u8) = null, // map watchdog IDs to paths
};
const DEFAULT_WIN32_FLAGS: win32.FileNotifyChangeFilter = .{};

//////////////////////
// PUBLIC FUNCTIONS //
//////////////////////

/// inits the internal Windows-specific data structures used by the watchdog.
/// must be called before any other Windows-specific watchdog operations.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
pub fn watchdogInit(p_wd: *zga.ZGA_WATCHDOG, alloc: std.mem.Allocator) !void {
    if (p_wd.has_been_init == true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.opt_hm_handle_to_path != null) return error.PATH_TO_HANDLE_HASHMAP_ALREADY_INIT;
    if (p_wd.platform_vars.opt_hm_path_to_handle != null) return error.HANDLE_TO_PATH_HASHMAP_ALREADY_INIT;

    // init hashmap for storing watchdog ptrs
    const path_to_handle_hm = std.StringHashMap(win32.HANDLE).init(alloc);
    errdefer path_to_handle_hm.deinit();
    const handle_to_path_hm = std.AutoHashMap(win32.HANDLE, []const u8).init(alloc);
    errdefer handle_to_path_hm.deinit();

    // if no errors have occurred --> set values now
    p_wd.platform_vars.opt_hm_path_to_handle = path_to_handle_hm;
    p_wd.platform_vars.opt_hm_handle_to_path = handle_to_path_hm;
}

/// adds a directory path to the watchlist
///
/// PARAMS:
/// - `path`: UTF-8 path to the directory to watch.
/// - `flags`: Bitmask of ZGA flags indicating which changes to monitor.
pub fn watchdogAdd(p_wd: *zga.ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
    _ = flags; // unused in Windows version

    // grabbing UTF-16 Le path for windows funcs using only stack allocations
    var utf8_temp_buf: [std.fs.max_path_bytes]u16 = undefined; // stack-allocated buffer for temporary conversions (only need half of this size --> leaving incase I've missed something)
    if (try std.unicode.checkUtf8ToUtf16LeOverflow(path, &utf8_temp_buf) == true) return error.UTF8_TEMP_BUF_WOULD_OVERFLOW; // avoid memory leak
    const num_indexes_written_lpcwstr: usize = try std.unicode.utf8ToUtf16Le(&utf8_temp_buf, path);
    const path_as_lpcwstr: [:0]const u16 = utf8_temp_buf[0..num_indexes_written_lpcwstr];

    // only creating new handle if one doesn't already exist --> will only happen on first attempt
    if (p_wd.platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        if (p_hm_path_to_handle.contains(path) == false) { // checking if hashmap value already exists
            const file_handle: win32.HANDLE = win32.kernel32.CreateFileW(   path_as_lpcwstr, 
                                                                            win32.FILE_LIST_DIRECTORY,
                                                                            win32.FILE_SHARE_READ | win32.FILE_SHARE_WRITE | win32.FILE_SHARE_DELETE,
                                                                            null,
                                                                            win32.OPEN_EXISTING,
                                                                            win32.FILE_FLAG_BACKUP_SEMANTICS,
                                                                            null,
                                                                        );
            if (file_handle == win32.INVALID_HANDLE_VALUE) return error.FAILED_TO_OPEN_DIR_WIN32;

            try p_hm_path_to_handle.put(path, file_handle);
            if (p_wd.platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| try p_hm_handle_to_path.put(file_handle, path) else return error.HM_HANDLE_TO_PATH_NOT_INIT;

        } else return error.ADDING_PATH_THAT_ALREADY_HAS_A_WATCHDOG;
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;
}

/// Removes a previously added path from the watchlist.
///
/// PARAMS:
/// - `path`: UTF-8 path to remove from watching.
pub fn watchdogRemove(p_wd: *zga.ZGA_WATCHDOG, path: []const u8) !void {
    // removing from handle --> path hashmap
    if (p_wd.platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| {
        if (p_wd.platform_vars.opt_hm_path_to_handle) |hm_path_to_handle| {
            const handle_to_remove: win32.HANDLE = hm_path_to_handle.get(path) orelse return error.HM_DOES_NOT_CONTAIN_PATH;

        if (p_hm_handle_to_path.contains(handle_to_remove) == true) { // checking if hashmap value exists
            if (p_hm_handle_to_path.remove(handle_to_remove) == false) return error.FAILED_TO_REMOVE_HANDLE_FROM_HM; // remove value from hashmap
        } else return error.PATH_DNE_IN_HM;

        // freeing memory associated with the handle
        win32.CloseHandle(handle_to_remove); 

        } return error.HM_PATH_TO_HANDLE_NOT_INIT;
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;

    // removing from path --> handle hashmap
    if (p_wd.platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        if (p_hm_path_to_handle.contains(path) == true) { // checking if hashmap value exists
            if (p_hm_path_to_handle.remove(path) == false) return error.FAILED_TO_REMOVE_PATH_FROM_HM; // remove value from hashmap
        } else return error.PATH_DNE_IN_HM;
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;
}

/// reads file change events from all watched directories and pushes them to the event queue.
///
/// PARAMS:
/// - `zga_flags`: Bitmask of ZGA event flags to filter which changes are captured.
pub fn watchdogRead(p_wd: *zga.ZGA_WATCHDOG, zga_flags: u32) !void {
    // buf to hold handle event info
    var buf: [MAX_NUM_EVENTS_PER_READ]u8 align(@alignOf(win32.FILE_NOTIFY_INFORMATION)) = undefined; 

    // collect all available handles
    if (p_wd.platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| {
        var handle_iterator = p_hm_handle_to_path.iterator();

        while (handle_iterator.next()) |hm_val| {
            const curr_handle: win32.HANDLE = hm_val.key_ptr.*;
            var bytes_returned: win32.DWORD = 0;

            // converting ZGA flags to Windows-specific flags
            const win32_flags: win32.FileNotifyChangeFilter = zgaToWin32Flags(zga_flags);
            if (std.meta.eql(win32_flags, DEFAULT_WIN32_FLAGS)) return error.INVALID_FLAGS_PARSED;
            const read_changes_result: win32.BOOL = win32.kernel32.ReadDirectoryChangesW(   curr_handle,
                                                                                    &buf, 
                                                                                    @intCast(buf.len), // usize --> DWORD
                                                                                    win32.FALSE,
                                                                                    win32_flags,
                                                                                    &bytes_returned,
                                                                                    null,
                                                                                    null,
                                                                                );
        
            // checking if failed capture from ReadDirectoryChangesW
            if (read_changes_result == win32.FALSE) return error.FAILED_ReadDirectoryChangesW_CALL;

            var offset: usize = 0; // init offset to iterate through the buffer of dir change events
            while (offset < bytes_returned) { // iterate over ea notify obj that is sent to buf of ReadDirectoryChangesW

                // calc filename ptr for collecting the file that changes act on
                const info: *win32.FILE_NOTIFY_INFORMATION = @ptrCast(@alignCast(&buf[offset]));
                const info_filename_start_loc_p_int: usize = @intFromPtr(&info.FileNameLength) + @sizeOf(win32.DWORD);
                const p_info_filename: [*]const u16 = @ptrFromInt(info_filename_start_loc_p_int);
                const name_len_wchar: usize = info.FileNameLength / 2; // in WCHARs

                // creating ZGA_EVENT obj from relevant vars
                var curr_event: zga.ZGA_EVENT = .{};
                curr_event.zga_flags = zga_flags;

                // conv UTF-16 filename slice to UTF-8 in a fixed buffer.
                const name_slice: []const u16 = p_info_filename[0..name_len_wchar];
                const bytes_written: usize = try std.unicode.utf16LeToUtf8(&curr_event.name_buf, name_slice); // writing to obj for queue
                curr_event.name = curr_event.name_buf[0..bytes_written]; // creating slice from num of bytes written to name buf

                // pushing current event to the global queue
                try p_wd.event_queue.writeItem(curr_event);

                // move to next event entry, or break if this is the last one
                if (info.NextEntryOffset == 0) break;
                offset += @intCast(info.NextEntryOffset);
            }
        }
    }
}

/// cleans up all Windows-specific watchdog resources and internal structures.
/// after this call, the watchdog must be re-initialised before use.
///
/// PARAMS:
/// - `p_wd`: Pointer to the ZGA_WATCHDOG object.
pub fn watchdogDeinit(p_wd: *zga.ZGA_WATCHDOG) void {
    // iterate over each wd_desc and call watchdogRemove on it + destroy the hashmap after doing so
    if (p_wd.platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        var hm_iterator = p_hm_path_to_handle.iterator();
        while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for freeing ea windows handle
            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
            watchdogRemove(p_wd, curr_hm_val_str) catch {}; // remove each hashmap key --> don't react to removal err to properly clean on end of func
        }

        // destroy the hashmap (path --> wd)
        p_hm_path_to_handle.deinit(); 

    }

    // destroying data structures --> heap allocated
    if (p_wd.platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| {
        p_hm_handle_to_path.deinit(); // destroy the hashmap (wd --> path)
    }

    // if no errors have occurred --> reset values now
    p_wd.platform_vars.opt_hm_path_to_handle = null;
    p_wd.platform_vars.opt_hm_handle_to_path = null;
}

///////////////////////
// PRIVATE FUNCTIONS //
///////////////////////

/// converts a Windows file change filter to a cross-platform ZGA event flag bitmask.
///
/// PARAMS:
/// - `win32_flags`: A Windows file change filter structure.
fn win32ToZGAFlags(win32_flags: win32.FileNotifyChangeFilter) u32 {
    var zga_mask: u32 = 0x0;

    // ignoring irrelevant or non-used win32-specific constants
    if (win32_flags.file_name == true) zga_mask |= zga.ZGA_MOVED;
    if (win32_flags.attributes == true) zga_mask |= zga.ZGA_ATTRIB;
    if (win32_flags.size == true) zga_mask |= zga.ZGA_MODIFIED;
    if (win32_flags.last_write == true) zga_mask |= zga.ZGA_MODIFIED;
    if (win32_flags.creation == true) zga_mask |= zga.ZGA_CREATE;
    if (win32_flags.last_access == true) zga_mask |= zga.ZGA_ACCESSED;

    return zga_mask;
}

/// converts a ZGA event flag bitmask into a Windows-compatible file change filter.
///
/// PARAMS:
/// - `zga_mask`: A bitmask composed of ZGA event flags.
fn zgaToWin32Flags(zga_mask: u32) win32.FileNotifyChangeFilter {
    var win32_flags: win32.FileNotifyChangeFilter = .{};

    if ((zga_mask & zga.ZGA_MOVED) != 0) win32_flags.file_name = true;
    if ((zga_mask & zga.ZGA_ATTRIB) != 0) win32_flags.attributes = true;
    if ((zga_mask & zga.ZGA_MODIFIED) != 0) win32_flags.size = true;
    if ((zga_mask & zga.ZGA_MODIFIED) != 0) win32_flags.last_write = true;
    if ((zga_mask & zga.ZGA_CREATE) != 0) win32_flags.creation = true;
    if ((zga_mask & zga.ZGA_ACCESSED) != 0) win32_flags.last_access = true;

    return win32_flags;
}