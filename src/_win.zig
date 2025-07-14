/// @file _win.zig
///
/// Implements a Windows win32-based filesystem watchdog for monitoring file and directory changes. 

/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const win32 = std.os.windows;
const zga = @import("zga.zig");
const builtin = @import("builtin");

///////////////////////////////
// MAGIC NUMBER DECLARATIONS //
///////////////////////////////

const MAX_NUM_EVENTS_PER_READ: comptime_int = 512;
const WIN32_READ_BUF_LEN = MAX_NUM_EVENTS_PER_READ * @sizeOf(win32.FILE_NOTIFY_INFORMATION);
const MAX_WATCHDOG_HANDLES: comptime_int = 64; // max number of directories to watch

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
    opt_iocp_handle: ?win32.HANDLE = null,
    opt_hm_path_to_handle: ?std.StringHashMap(win32.HANDLE) = null, // map paths to watchdog IDs
    opt_hm_handle_to_path: ?std.AutoHashMap(win32.HANDLE, []const u8) = null, // map watchdog IDs to paths
    opt_hm_handle_to_overlapped: ?std.AutoHashMap(win32.HANDLE, OVERLAPPED_STATE) = null, // map directory handles to OVERLAPPED_STATEs
};
const DEFAULT_WIN32_FLAGS: win32.FileNotifyChangeFilter = .{};

/////////////////////////////////
// PRIVATE STRUCT DECLARATIONS //
/////////////////////////////////

const OVERLAPPED_STATE = struct {
    ov: win32.OVERLAPPED = undefined,
    buf: [WIN32_READ_BUF_LEN]u8 align(@alignOf(win32.FILE_NOTIFY_INFORMATION)) = undefined,
};

////////////////////////////////////
// EXTERNAL FUNCTION DECLARATIONS //
////////////////////////////////////

extern "kernel32" fn ReadDirectoryChangesW(hDirectory: win32.HANDLE, lpBuffer: win32.LPVOID, nBufferLength: win32.DWORD, 
                                        bWatchSubtree: win32.BOOL, dwNotifyFilter: win32.DWORD, 
                                        lpBytesReturned: ?*win32.DWORD, lpOverlapped: ?*win32.OVERLAPPED, lpCompletionRoutine: ?*const void,) callconv(.winapi) win32.BOOL;
extern "kernel32" fn ResetEvent(hEvent: win32.HANDLE) callconv(.winapi) win32.BOOL;

//////////////////////
// PUBLIC FUNCTIONS //
//////////////////////

/// inits the internal Windows-specific data structures used by the watchdog.
/// must be called before any other Windows-specific watchdog operations.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the WIN32_VARS object used for storing variables relevant to inotify
/// - `alloc`: Allocator for internal values.
pub fn watchdogInit(p_platform_vars: *WIN32_VARS, alloc: std.mem.Allocator) !void {
    if (p_platform_vars.opt_hm_handle_to_path != null) return error.HM_HANDLE_TO_PATH_INIT_ALREADY;
    if (p_platform_vars.opt_hm_path_to_handle != null) return error.HM_PATH_TO_HANDLE_INIT_ALREADY;
    if (p_platform_vars.opt_hm_handle_to_overlapped != null) return error.HM_HANDLE_TO_OVERLAPPED_AKREADY_INIT;
    if (p_platform_vars.opt_iocp_handle != null) return error.IOCP_HANDLE_ALREADY_INIT;

    // init hashmap for storing watchdog ptrs
    var path_to_handle_hm = std.StringHashMap(win32.HANDLE).init(alloc);
    errdefer path_to_handle_hm.deinit();
    var handle_to_path_hm = std.AutoHashMap(win32.HANDLE, []const u8).init(alloc);
    errdefer handle_to_path_hm.deinit();
    var handle_to_overlapped_hm = std.AutoHashMap(win32.HANDLE, OVERLAPPED_STATE).init(alloc);
    errdefer handle_to_overlapped_hm.deinit();

    // init iocp handler --> for efficient, async I/O
    const iocp: win32.HANDLE = win32.kernel32.CreateIoCompletionPort(win32.INVALID_HANDLE_VALUE, null, 0x0, 0) orelse return error.IOCP_FAILED_INIT;

    // if no errors have occurred --> set values now
    p_platform_vars.opt_hm_path_to_handle = path_to_handle_hm;
    p_platform_vars.opt_hm_handle_to_path = handle_to_path_hm;
    p_platform_vars.opt_iocp_handle = iocp;
    p_platform_vars.opt_hm_handle_to_overlapped = handle_to_overlapped_hm;
}

/// adds a directory path to the watchlist
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the WIN32_VARS object used for storing variables relevant to inotify
/// - `path`: UTF-8 path to the directory to watch.
/// - `flags`: Bitmask of ZGA flags indicating which changes to monitor.
pub fn watchdogAdd(p_platform_vars: *WIN32_VARS, path: []const u8, flags: u32) !void {
    if (p_platform_vars.opt_hm_handle_to_path == null) return error.HM_HANDLE_TO_PATH_NOT_INIT;
    if (p_platform_vars.opt_hm_path_to_handle == null) return error.HM_PATH_TO_HANDLE_NOT_INIT;
    if (p_platform_vars.opt_hm_handle_to_overlapped == null) return error.HM_HANDLE_TO_OVERLAPPED_NOT_INIT;
    if (p_platform_vars.opt_iocp_handle == null) return error.IOCP_HANDLE_NOT_INIT;

    // checking if path is valid on target system
    if (path.len >= zga.MAX_PATH_SIZE) return error.WIN32_PATH_TOO_LONG;
    const cwd: std.fs.Dir = std.fs.cwd();
    try cwd.access(path, .{});

    // grabbing UTF-16 Le path for windows funcs using only stack allocations
    var utf8_temp_buf: [zga.MAX_PATH_SIZE]u16 = undefined; // stack-allocated buffer for temporary conversions (only need half of this size --> leaving incase I've missed something)
    if (try std.unicode.checkUtf8ToUtf16LeOverflow(path, &utf8_temp_buf) == true) return error.UTF8_TEMP_BUF_WOULD_OVERFLOW; // avoid memory leak
    const num_indexes_written_lpcwstr: usize = try std.unicode.utf8ToUtf16Le(&utf8_temp_buf, path);

    // null-terminating resultant string and converting to slice
    utf8_temp_buf[num_indexes_written_lpcwstr] = 0x0; // setting last character to the null-terminator
    const path_as_lpcwstr: [:0]const u16 = utf8_temp_buf[0..num_indexes_written_lpcwstr :0];

    // only creating new handle if one doesn't already exist --> will only happen on first attempt
    if (p_platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        if (p_hm_path_to_handle.contains(path) == false) { // checking if hashmap value already exists
            const file_handle: win32.HANDLE = win32.kernel32.CreateFileW(   path_as_lpcwstr, 
                                                                            win32.FILE_LIST_DIRECTORY,
                                                                            win32.FILE_SHARE_READ | win32.FILE_SHARE_WRITE | win32.FILE_SHARE_DELETE,
                                                                            null,
                                                                            win32.OPEN_EXISTING,
                                                                            win32.FILE_FLAG_BACKUP_SEMANTICS | win32.FILE_FLAG_OVERLAPPED, // async enabled
                                                                            null,
                                                                        );
            errdefer win32.CloseHandle(file_handle);
            if (file_handle == win32.INVALID_HANDLE_VALUE) return error.FAILED_TO_OPEN_DIR_WIN32;

            // associating existing IOCP with new file handle
            if (p_platform_vars.opt_iocp_handle) |iocp_handle| {
                const iosc_assoc = win32.kernel32.CreateIoCompletionPort(file_handle, iocp_handle, @intFromPtr(file_handle), 0);
                if (iosc_assoc == null) return error.FAILED_TO_ASSOC_IOCP;
            } else return error.IOCP_HANDLE_NOT_INIT;

            // adding the path --> handle to the correct HM
            try p_hm_path_to_handle.put(path, file_handle);

            // adding the handle --> path to the correct HM
            if (p_platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| {
                try p_hm_handle_to_path.put(file_handle, path);
            } else return error.HM_HANDLE_TO_PATH_NOT_INIT;

            // grabbing windows flags from ZGA flags
            const win32_flags: win32.FileNotifyChangeFilter = zgaToWin32Flags(flags);
            if (win32_flags == DEFAULT_WIN32_FLAGS) return error.INVALID_FLAGS_PARSED; // if no selections

            if (p_platform_vars.opt_hm_handle_to_overlapped) |*p_hm_handle_to_overlapped| {
                // collecting overlapped ptr from hashmap (for use past stack expiry)
                try p_hm_handle_to_overlapped.put(file_handle, .{}); // put template ov_state
                const p_ov_state: *OVERLAPPED_STATE = p_hm_handle_to_overlapped.getPtr(file_handle) orelse return error.HM_HANDLE_NOT_VALID;

                // call first instance of ReadDirectoryChangesW to start async poll
                const buf_slice: []align(@alignOf(win32.FILE_NOTIFY_INFORMATION))u8 = p_ov_state.buf[0..p_ov_state.buf.len]; // slice maps entire buffer
                const p_aligned_buf_slice: [*]align(@alignOf(win32.FILE_NOTIFY_INFORMATION))u8 = buf_slice.ptr; // aligned ptr to buf slice
                const init_read_dir_res: win32.BOOL = win32.kernel32.ReadDirectoryChangesW(
                    file_handle,
                    p_aligned_buf_slice,
                    @intCast(p_ov_state.buf.len),
                    win32.TRUE,
                    win32_flags,
                    null, // no bytes returned asynchronously
                    &p_ov_state.ov,
                    null, // no completion routine, since using IOCP
                );
                if (init_read_dir_res == win32.FALSE and win32.kernel32.GetLastError() != .IO_PENDING) return error.INVALID_INIT_READ_DIR;
            }

        } else return error.HM_PATH_TO_HANDLE_ALREADY_CONTAINS_PATH;

    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;
}

/// Removes a previously added path from the watchlist.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the WIN32_VARS object used for storing variables relevant to inotify
/// - `path`: UTF-8 path to remove from watching.
pub fn watchdogRemove(p_platform_vars: *WIN32_VARS, path: []const u8) !void {
    if (p_platform_vars.opt_hm_handle_to_path == null) return error.HM_HANDLE_TO_PATH_NOT_INIT;
    if (p_platform_vars.opt_hm_path_to_handle == null) return error.HM_PATH_TO_HANDLE_NOT_INIT;
    if (p_platform_vars.opt_hm_handle_to_overlapped == null) return error.HM_HANDLE_TO_OVERLAPPED_NOT_INIT;
    if (p_platform_vars.opt_iocp_handle == null) return error.IOCP_HANDLE_NOT_INIT;

    if (p_platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| {
        if (p_platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
            const handle_to_remove: win32.HANDLE = p_hm_path_to_handle.get(path) orelse return error.HM_DOES_NOT_CONTAIN_PATH;

            // removing from handle --> ov_state hashmap
            if (p_platform_vars.opt_hm_handle_to_overlapped) |*p_hm_handle_to_ov| {

                if (p_hm_handle_to_ov.contains(handle_to_remove) == true) {
                    if (p_hm_handle_to_ov.remove(handle_to_remove) == false) return error.FAILED_TO_REMOVE_HANDLE_FROM_HM; // remove val from hashmap
                }

            }

            // removing from handle --> path hashmap
            if (p_hm_handle_to_path.contains(handle_to_remove) == true) { 

                if (p_hm_handle_to_path.remove(handle_to_remove) == false) return error.FAILED_TO_REMOVE_HANDLE_FROM_HM; // remove value from hashmap

            } else return error.HM_HANDLE_TO_PATH_DOES_NOT_CONTAIN_HANDLE;

            // freeing memory associated with the handle
            win32.CloseHandle(handle_to_remove); 

            // removing from path --> handle hashmap
            if (p_hm_path_to_handle.contains(path) == true) { // checking if hashmap value exists

                if (p_hm_path_to_handle.remove(path) == false) return error.FAILED_TO_REMOVE_PATH_FROM_HM; // remove value from hashmap

            } else return error.PATH_DNE_IN_HM;

        } else return error.HM_HANDLE_TO_PATH_NOT_INIT;
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;
}

/// reads file change events from all watched directories and pushes them to the event queue.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the WIN32_VARS object used for storing variables relevant to inotify
/// - `zga_flags`: Bitmask of ZGA event flags to filter which changes are captured.
/// - `p_event_queue`: Pointer to the event queue used for storing file events from the watchdog
/// - `p_error_queue`: Pointer to the error queue used for storing error events from the watchdog
pub fn watchdogRead(p_platform_vars: *WIN32_VARS, zga_flags: u32, p_event_queue: *std.fifo.LinearFifo(zga.ZGA_EVENT, .Slice), p_error_queue: *std.fifo.LinearFifo(anyerror, .Slice)) !void {
    if (p_platform_vars.opt_hm_handle_to_path == null) return error.HM_HANDLE_TO_PATH_NOT_INIT;
    if (p_platform_vars.opt_hm_path_to_handle == null) return error.HM_PATH_TO_HANDLE_NOT_INIT;
    if (p_platform_vars.opt_hm_handle_to_overlapped == null) return error.HM_HANDLE_TO_OVERLAPPED_NOT_INIT;
    if (p_platform_vars.opt_iocp_handle == null) return error.IOCP_HANDLE_NOT_INIT;

    // collect queued completion entries (blocking wait)
    var num_completed_entries: u32 = 0;
    var completion_io_entries: [MAX_WATCHDOG_HANDLES]win32.OVERLAPPED_ENTRY = undefined;
    if (p_platform_vars.opt_iocp_handle) |iocp_handle| {
        const queued_completion_ok: win32.BOOL = win32.kernel32.GetQueuedCompletionStatusEx(
            iocp_handle,
            &completion_io_entries,
            MAX_WATCHDOG_HANDLES,
            &num_completed_entries,
            win32.INFINITE,
            win32.FALSE,
        );
        if (queued_completion_ok == win32.FALSE) { // fail if queued_completion is not successful
            const last_err: u16 = @intFromEnum(win32.kernel32.GetLastError());
            try p_error_queue.writeItem(@errorFromInt(last_err));
            return error.QUEUED_COMPLETION_NOT_OK;
        }

        // iterate over all completed IO entries
        var i: usize = 0;
        while (i < num_completed_entries) : (i += 1) {
            const entry: win32.OVERLAPPED_ENTRY = completion_io_entries[i];
            const curr_handle: win32.HANDLE = @ptrFromInt(entry.lpCompletionKey); // works because we passed @intFromPtr(file_handle) as the key when calling CreateIoCompletionPort.
            const bytes_transferred: u32 = entry.dwNumberOfBytesTransferred;

            if (p_platform_vars.opt_hm_handle_to_overlapped) |*p_hm_handle_to_ov| {
                const p_ov_state: *OVERLAPPED_STATE = p_hm_handle_to_ov.getPtr(curr_handle) orelse continue;
                const p_buf: *[WIN32_READ_BUF_LEN]u8 align(@alignOf(win32.FILE_NOTIFY_INFORMATION)) = &p_ov_state.buf;

                // parse all events within the transferred byte range
                var offset: usize = 0;
                while (offset < bytes_transferred) {
                    const info: *win32.FILE_NOTIFY_INFORMATION = @ptrCast(@alignCast(&p_buf[offset]));
                    const name_len_wchar: usize = info.FileNameLength / 2;
                    
                    // filename is located after FileNameLength field (DWORD)
                    const p_filename_int: usize = @intFromPtr(&info.NextEntryOffset) + @sizeOf(@TypeOf(info.NextEntryOffset)) + @sizeOf(@TypeOf(info.Action)) + @sizeOf(@TypeOf(info.FileNameLength)); // typedef struct _FILE_NOTIFY_INFORMATION { DWORD NextEntryOffset; DWORD Action; DWORD FileNameLength; WCHAR FileName[1]; } FILE_NOTIFY_INFORMATION, *PFILE_NOTIFY_INFORMATION;
                    const p_info_filename: [*]const u16 = @ptrFromInt(p_filename_int);
                    const name_utf16: []const u16 = p_info_filename[0..name_len_wchar];

                    std.debug.print("{any}\n", .{name_utf16});

                    // create and enqueue event
                    var curr_event: zga.ZGA_EVENT = .{};
                    curr_event.zga_flags = zga_flags;
                    curr_event.name_len = try std.unicode.utf16LeToUtf8(&curr_event.name_buf, name_utf16);
                    try p_event_queue.writeItem(curr_event);

                    // break if this is the final entry
                    if (info.NextEntryOffset == 0) break;
                    offset += info.NextEntryOffset; // otherwise increment offset to next entry
                }

                // extract win32 flags from ZGA bitmask
                const win32_flags: win32.FileNotifyChangeFilter = zgaToWin32Flags(zga_flags);
                if (win32_flags == DEFAULT_WIN32_FLAGS) return error.INVALID_FLAGS_PARSED; // if no selections

                // re-issue ReadDirectoryChangesW to continue watching
                const buf_slice: []align(@alignOf(win32.FILE_NOTIFY_INFORMATION))u8 = p_ov_state.buf[0..p_ov_state.buf.len]; // slice maps entire buffer
                const p_aligned_buf_slice: [*]align(@alignOf(win32.FILE_NOTIFY_INFORMATION))u8 = buf_slice.ptr; // aligned ptr to buf slice
                const res: win32.BOOL = win32.kernel32.ReadDirectoryChangesW(
                    curr_handle,
                    p_aligned_buf_slice,
                    @intCast(p_ov_state.buf.len),
                    win32.TRUE,
                    win32_flags,
                    null,
                    &p_ov_state.ov,
                    null,
                );

                // log re-issue errors (only if not async expected)
                if (res == win32.FALSE and win32.kernel32.GetLastError() != .IO_PENDING) try p_error_queue.writeItem(error.FAILED_Reissue_ReadDirectoryChangesW);
            } else return error.HM_HANDLE_TO_OVERLAPPED_NOT_INIT;
        }
    } else return error.IOCP_HANDLE_NOT_INIT;
}

/// Returns a slice of filepath strings that are currently being watched. The returned slice must be deallocated externally after use.
/// 
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
/// - `alloc`: Allocator for internal values.
pub fn watchdogList(p_platform_vars: *WIN32_VARS, alloc: std.mem.Allocator) ![]const []const u8 {
    if (p_platform_vars.opt_hm_handle_to_path == null) return error.HM_HANDLE_TO_PATH_NOT_INIT;
    if (p_platform_vars.opt_hm_path_to_handle == null) return error.HM_PATH_TO_HANDLE_NOT_INIT;
    if (p_platform_vars.opt_hm_handle_to_overlapped == null) return error.HM_HANDLE_TO_OVERLAPPED_NOT_INIT;
    if (p_platform_vars.opt_iocp_handle == null) return error.IOCP_HANDLE_NOT_INIT;

    var wd_watchlist = std.ArrayList([]const u8).init(alloc);

    if (p_platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        var hm_iterator = p_hm_path_to_handle.iterator();
        while (hm_iterator.next()) |hm_val| {
            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting path key from hashmap "Entry"
            try wd_watchlist.append(curr_hm_val_str);
        }
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;

    return wd_watchlist;
}

/// cleans up all Windows-specific watchdog resources and internal structures.
/// after this call, the watchdog must be re-initialised before use.
///
/// PARAMS:
/// - `p_platform_vars`: Pointer to the INOTIFY_VARS object used for storing variables relevant to inotify
pub fn watchdogDeinit(p_platform_vars: *WIN32_VARS) void {
    // iterate over each wd_desc and call watchdogRemove on it + destroy the hashmap after doing so
    if (p_platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        var hm_iterator = p_hm_path_to_handle.iterator();
        while (hm_iterator.next()) |hm_val| { // iterate over all hashmap values --> required for freeing ea windows handle
            const curr_hm_val_str: []const u8 = hm_val.key_ptr.*; // collecting the key from the hashmap "Entry"
            watchdogRemove(p_platform_vars, curr_hm_val_str) catch {}; // remove each hashmap key --> don't react to removal err to properly clean on end of func
        }

        // destroy the hashmap (path --> wd)
        p_hm_path_to_handle.deinit(); 

    } // don't return error if already null --> being set to null anyways

    // destroy the hashmap (wd --> path)
    if (p_platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| p_hm_handle_to_path.deinit(); // don't return error if already null --> being set to null anyways

    // Closing IOCP handle
    if (p_platform_vars.opt_iocp_handle) |iocp_handle| {
        win32.CloseHandle(iocp_handle);
    }

    // destroy the hashmap (wd --> ov)
    if (p_platform_vars.opt_hm_handle_to_overlapped) |*p_hm_handle_to_ov| p_hm_handle_to_ov.deinit(); // don't return error if already null --> being set to null anyways

    // if no errors have occurred --> reset values now
    p_platform_vars.opt_hm_path_to_handle = null;
    p_platform_vars.opt_hm_handle_to_path = null;
    p_platform_vars.opt_iocp_handle = null;
    p_platform_vars.opt_hm_handle_to_overlapped = null;
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
    // don't check for security (currently not avail in ZGA)

    return zga_mask;
}

/// converts a ZGA event flag bitmask into a Windows-compatible file change filter.
///
/// PARAMS:
/// - `zga_mask`: A bitmask composed of ZGA event flags.
fn zgaToWin32Flags(zga_mask: u32) win32.FileNotifyChangeFilter {
    var win32_flags: win32.FileNotifyChangeFilter = .{};

    if ((zga_mask & zga.ZGA_MOVED) != 0) win32_flags.file_name = true;
    if ((zga_mask & zga.ZGA_MOVED) != 0) win32_flags.dir_name = true;
    if ((zga_mask & zga.ZGA_ATTRIB) != 0) win32_flags.attributes = true;
    if ((zga_mask & zga.ZGA_MODIFIED) != 0) win32_flags.size = true;
    if ((zga_mask & zga.ZGA_MODIFIED) != 0) win32_flags.last_write = true; 
    if ((zga_mask & zga.ZGA_ACCESSED) != 0) win32_flags.last_access = true;
    if ((zga_mask & zga.ZGA_CREATE) != 0) win32_flags.creation = true;
    // if ((zga_mask & zga.ZGA_SECURITY) != 0) win32_mask |= FILE_NOTIFY_CHANGE_SECURITY; // don't check for security (currently not avail in ZGA)

    return win32_flags;
}

///////////////////////////
// PUBLIC FUNCTION TESTS //
///////////////////////////

// watchdogInit //

test "watchdogInit: inits empty internal hashmaps" {
    // create wd object
    var wd: zga.ZGA_WATCHDOG = .{};
    const alloc: std.mem.Allocator = std.testing.allocator;

    // - Expect hashmaps to be null before
    try std.testing.expect(wd.platform_vars.opt_hm_handle_to_path == null);
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_handle == null);

    // - Call watchdogInit
    try watchdogInit(&wd.platform_vars, alloc);

    // - Expect hashmaps to be non-null after
    try std.testing.expect(wd.platform_vars.opt_hm_handle_to_path != null);
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_handle != null);

    // - Test error on double init
    const res2 = watchdogInit(&wd.platform_vars, alloc);
    try std.testing.expectError(error.HM_HANDLE_TO_PATH_INIT_ALREADY, res2);
}

// watchdogAdd //

test "watchdogAdd: fails if not init" {
    // - Create obj
    var wd: zga.ZGA_WATCHDOG = .{};

    // create tmp testing dir
    const tmp_dir: std.testing.TmpDir = std.testing.tmpDir(.{});
    const tmp_dir_loc: []const u8 = &tmp_dir.sub_path;

    // - Pass uninit WIN32_VARS
    const result = watchdogAdd(&wd.platform_vars, tmp_dir_loc, zga.ZGA_CREATE);

    // - Expect correct error return
    try std.testing.expectError(error.HM_HANDLE_TO_PATH_NOT_INIT, result);

}

test "watchdogAdd: successfully adds a valid path" {
    // - Init watchdog
    var wd: zga.ZGA_WATCHDOG = .{};
    const alloc: std.mem.Allocator = std.testing.allocator;
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // - Create temporary test directory
    // const tmp_dir: std.testing.TmpDir = std.testing.tmpDir(.{});
    // const tmp_dir_loc: []const u8 = &tmp_dir.sub_path;
    const tmp_dir_loc: []const u8 = "./test";

    // - Add directory path
    try watchdogAdd(&wd.platform_vars, tmp_dir_loc, zga.ZGA_ACCESSED);

    // - Ensure that hashmaps are still initialised
    try std.testing.expect(wd.platform_vars.opt_hm_handle_to_path != null);
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_handle != null);

    // - Ensure handle stored in both hashmaps
    const opt_handle_from_path = wd.platform_vars.opt_hm_path_to_handle.?.get(tmp_dir_loc);
    try std.testing.expect(opt_handle_from_path != null);

    const opt_path_from_handle = wd.platform_vars.opt_hm_handle_to_path.?.get(opt_handle_from_path.?);
    try std.testing.expect(opt_path_from_handle != null);
}

test "watchdogAdd: fails on duplicate path" {
    // - Init watchdog
    var wd: zga.ZGA_WATCHDOG = .{};
    const alloc: std.mem.Allocator = std.testing.allocator;
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // - Add the same path twice
    try watchdogAdd(&wd.platform_vars, "./test", zga.ZGA_CREATE);
    const result = watchdogAdd(&wd.platform_vars, "./test", zga.ZGA_DELETE);

    // - Ensure appropriate error is returned
    try std.testing.expectError(error.HM_PATH_TO_HANDLE_ALREADY_CONTAINS_PATH, result);
}

test "watchdogAdd: fails if opt_hm_path_to_handle == null" {
    // - Init watchdog
    var wd: zga.ZGA_WATCHDOG = .{};
    const alloc: std.mem.Allocator = std.testing.allocator;
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // set opt_hm_path_to_handle to null
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_handle != null);
    wd.platform_vars.opt_hm_path_to_handle.?.deinit();
    wd.platform_vars.opt_hm_path_to_handle = null;

    // add new watch location
    const result = watchdogAdd(&wd.platform_vars, "./test", zga.ZGA_ATTRIB);

    // Ensure that correct error is responded
    try std.testing.expectError(error.HM_PATH_TO_HANDLE_NOT_INIT, result);
}

test "watchdogAdd: fails if opt_hm_handle_to_path == null" {
    // - Init watchdog
    var wd: zga.ZGA_WATCHDOG = .{};
    const alloc: std.mem.Allocator = std.testing.allocator;
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // set opt_hm_handle_to_path to null
    try std.testing.expect(wd.platform_vars.opt_hm_handle_to_path != null);
    wd.platform_vars.opt_hm_handle_to_path.?.deinit();
    wd.platform_vars.opt_hm_handle_to_path = null;

    // add new watch location
    const result = watchdogAdd(&wd.platform_vars, "./test", zga.ZGA_ATTRIB);

    // Ensure that correct error is responded
    try std.testing.expectError(error.HM_HANDLE_TO_PATH_NOT_INIT, result);

}

test "watchdogAdd: invalid path provided (length not of valid path length)" {
    // - Init watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // - Add invalid path w/ length > win32.PATH_MAX_WIDE (win32 --> must be greater than 37,767 bytes)
    const buf: []u8 = try alloc.alloc(u8, zga.MAX_PATH_SIZE);
    defer alloc.free(buf);
    for (buf) |*p_c| p_c.* = 'A'; // setting all values in buffer to 'A' (x100_000)
    try std.testing.expectEqualStrings(buf[0..10], "AAAAAAAAAA");

    // - Add watchdog from path that is huge
    const result = watchdogAdd(&wd.platform_vars, buf, zga.ZGA_CREATE);

    // - Check that error returns as expected
    try std.testing.expectError(error.WIN32_PATH_TOO_LONG, result);
}

test "watchdogAdd: path not valid on target system" {
    // - Init watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // Attempt to add invalid path through win32 API
    const result = watchdogAdd(&wd.platform_vars, "./this_path_should_never_exist.abcdefg", zga.ZGA_CREATE);

    // Check that error is returned for invalid watch path
    try std.testing.expectError(error.FileNotFound, result);
}

// watchdogRemove //

test "watchdogRemove: fails if not initialized" {
    // - Use uninit WIN32_VARS
    var wd: zga.ZGA_WATCHDOG = .{};

    // - Try to remove path, check for error
    const result = watchdogRemove(&wd.platform_vars, "./test/test_file1.txt");

    // Should return error for uninit wd
    try std.testing.expectError(error.HM_HANDLE_TO_PATH_NOT_INIT, result);
}

test "watchdogRemove: fails if path does not exist" {
    // - Init watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // - Remove path not added
    const result = watchdogRemove(&wd.platform_vars, "./test/test_file1.txt");

    // - Check for correct error
    try std.testing.expectError(error.HM_DOES_NOT_CONTAIN_PATH, result);
}

test "watchdogRemove: removes valid path and handle" {
    // - Init watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // - Add path
    try watchdogAdd(&wd.platform_vars, "./test/test_file1.txt", zga.ZGA_CREATE);

    // - Ensure that hashmaps are valid
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_handle != null);
    try std.testing.expect(wd.platform_vars.opt_hm_handle_to_path != null);

    // - Ensure entries added to hashmap
    const result1 = wd.platform_vars.opt_hm_path_to_handle.?.get("./test/test_file1.txt");
    try std.testing.expect(result1 != null);
    const result2 = wd.platform_vars.opt_hm_handle_to_path.?.get(result1.?);
    try std.testing.expect(result2 != null);
    
    // storing handle for check later (after free)
    const handle_slice = try alloc.alloc(win32.HANDLE, 1);
    defer alloc.free(handle_slice);
    @memset(handle_slice, result1.?);
    
    // - Remove path
    try watchdogRemove(&wd.platform_vars, "./test/test_file1.txt");

    // - Ensure that hashmaps are still valid
    try std.testing.expect(wd.platform_vars.opt_hm_path_to_handle != null);
    try std.testing.expect(wd.platform_vars.opt_hm_handle_to_path != null);

    // - Ensure entries removed from hashmaps (and handle closed)
    const result3 = wd.platform_vars.opt_hm_path_to_handle.?.get("./test/test_file1.txt");
    try std.testing.expect(result3 == null);
    const result4 = wd.platform_vars.opt_hm_handle_to_path.?.get(handle_slice[0]);
    try std.testing.expect(result4 == null);
}

// watchdogRead //

test "watchdogRead: fails if not initialized" {
    // - Create uninit WIN32_VARS
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};

    // creating buffers for valid watchdogRead
    const event_buf: []zga.ZGA_EVENT = try alloc.alloc(zga.ZGA_EVENT, zga.SIZE_EVENT_QUEUE);
    defer alloc.free(event_buf);
    const error_buf: []anyerror = try alloc.alloc(anyerror, zga.SIZE_ERROR_QUEUE);
    defer alloc.free(error_buf);
    var event_queue = std.fifo.LinearFifo(zga.ZGA_EVENT, .Slice).init(event_buf); // init the LinearFIFO 
    var error_queue = std.fifo.LinearFifo(anyerror, .Slice).init(error_buf); // init the LinearFIFO 

    // - Pass uninit WIN32_VARS to watchdogRead
    const result = watchdogRead(&wd.platform_vars, zga.ZGA_CREATE, &event_queue, &error_queue);

    // - Ensure correct error is returned
    try std.testing.expectError(error.HM_HANDLE_TO_PATH_NOT_INIT, result);
}

test "watchdogRead: returns valid events on change" {
    // init watchdog
    const alloc: std.mem.Allocator = std.testing.allocator;
    var wd: zga.ZGA_WATCHDOG = .{};
    try watchdogInit(&wd.platform_vars, alloc);
    defer watchdogDeinit(&wd.platform_vars);

    // creating buffers for valid watchdogRead
    const event_buf: []zga.ZGA_EVENT = try alloc.alloc(zga.ZGA_EVENT, zga.SIZE_EVENT_QUEUE);
    defer alloc.free(event_buf);
    const error_buf: []anyerror = try alloc.alloc(anyerror, zga.SIZE_ERROR_QUEUE);
    defer alloc.free(error_buf);
    var event_queue = std.fifo.LinearFifo(zga.ZGA_EVENT, .Slice).init(event_buf); // init the LinearFIFO 
    var error_queue = std.fifo.LinearFifo(anyerror, .Slice).init(error_buf); // init the LinearFIFO 

    // - Create temp directory for storing files
    var tmp_dir: std.testing.TmpDir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var tmp_dir_loc_buf: [zga.MAX_PATH_SIZE]u8 = undefined;
    const tmp_dir_loc: []const u8 = try tmp_dir.parent_dir.realpath(".", tmp_dir_loc_buf[0..zga.MAX_PATH_SIZE]);
    
    // - Add path watcher
    try watchdogAdd(&wd.platform_vars, tmp_dir_loc, zga.ZGA_CREATE | zga.ZGA_MOVED | zga.ZGA_ACCESSED);

    // - Read events --> does not work like inotify version --> does not show previous events before call
    try watchdogRead(&wd.platform_vars, zga.ZGA_CREATE, &event_queue, &error_queue);

    // Creating files to check against watchdogRead
    const file_creation_path: []const u8 = try std.fmt.allocPrint(alloc, "{s}/threaded_temp_file.txt", .{tmp_dir_loc});
    defer alloc.free(file_creation_path);
    var cwd = std.fs.cwd();
    const file = try cwd.createFile(file_creation_path, .{});
    file.close();
    _ = try cwd.deleteFile(file_creation_path);

    // // - Pull events from the queue --> checking that they exist
    // const create_event = event_queue.readItem();
    // try std.testing.expect(create_event != null);
    // const delete_event = event_queue.readItem();
    // try std.testing.expect(delete_event != null);

    // // - Verify that create_event acts as expected
    // try std.testing.expect(create_event.?.zga_flags == zga.ZGA_CREATE);
    // try std.testing.expectEqualStrings(create_event.?.name_buf[0..create_event.?.name_len], "./test/wd_read_test_file_987654321.txt");

    // // - Verify that delete_event acts as expected
    // try std.testing.expect(delete_event.?.zga_flags == zga.ZGA_DELETE);
    // try std.testing.expectEqualStrings(delete_event.?.name_buf[0..delete_event.?.name_len], "./test/wd_read_test_file_987654321.txt");   
}

test "watchdogRead: Successfully reads and processes multiple of the same events after deactivation and reactivation" {

}

test "watchdogRead: returns correct zga_flags" {
    // - Add path with specific zga_flags
    // - Make appropriate changes (e.g., rename, write)
    // - Validate that event.zga_flags matches expected ones
}

// watchdogList //

test "watchdogList: fails if not initialized" {
    // - Call watchdogList on uninitialized WIN32_VARS
    // - Expect correct error
}

test "watchdogList: returns correct paths" {
    // - Add multiple paths
    // - Call watchdogList
    // - Confirm all paths are listed
}

// watchdogDeinit //

test "watchdogDeinit: cleans up all handles and hashmaps" {
    // - Add multiple paths
    // - Call watchdogDeinit
    // - Confirm hashmaps are null and handles are closed
}

////////////////////////////
// PRIVATE FUNCTION TESTS //
////////////////////////////

// zgaToWin32Flags //

test "zgaToWin32Flags: converts ZGA flags to correct Win32 filter" {
    // - Provide ZGA flags
    // - Verify each corresponding Win32 field is set correctly
}

// win32ToZGAFlags //

test "win32ToZGAFlags: converts Win32 filter to correct ZGA flags" {
    // - Provide Win32 flags
    // - Verify returned ZGA bitmask matches
}

////////////////////
// TEST FUNCTIONS //
////////////////////

