/////////////
// IMPORTS // 
/////////////

const std = @import("std");
const win32 = std.os.windows;
const zga = @import("zga.zig");

///////////////////////////////
// MAGIC NUMBER DECLARATIONS //
///////////////////////////////

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

/////////////////////////////////
// PRIVATE STRUCT DECLARATIONS //
/////////////////////////////////

const OVER_DUMMYSTRUCTNAME = extern struct {
    Offset: win32.DWORD,
    OffsetHigh: win32.DWORD,
};

const OVER_DUMMYUNIONNAME = extern union {
    Struct: OVER_DUMMYSTRUCTNAME,
    Pointer: win32.PVOID,
};

const OVERLAPPED = extern struct {
    Internal: win32.ULONG_PTR,
    InternalHigh: win32.ULONG_PTR,
    Union: OVER_DUMMYUNIONNAME,
    hEvent: win32.HANDLE,
};

///////////////////////////
// WINDOWS API FUNCTIONS //
///////////////////////////

//////////////////////
// PUBLIC FUNCTIONS //
//////////////////////

pub fn watchdogInit(p_wd: *zga.ZGA_WATCHDOG) !void {
    if (p_wd.has_been_init == true) return error.WATCHDOG_ALREADY_INIT;
    if (p_wd.platform_vars.opt_hm_handle_to_path != null) return error.PATH_TO_HANDLE_HASHMAP_ALREADY_INIT;
    if (p_wd.platform_vars.opt_hm_path_to_handle != null) return error.HANDLE_TO_PATH_HASHMAP_ALREADY_INIT;

    // init hashmap for storing watchdog ptrs
    if (p_wd.alloc) |l_alloc| {
        const path_to_handle_hm = std.StringHashMap(win32.HANDLE).init(l_alloc);
        errdefer path_to_handle_hm.deinit();
        const handle_to_path_hm = std.AutoHashMap(win32.HANDLE, []const u8).init(l_alloc);
        errdefer handle_to_path_hm.deinit();

        // if no errors have occurred --> set values now
        p_wd.platform_vars.opt_hm_path_to_handle = path_to_handle_hm;
        p_wd.platform_vars.opt_hm_handle_to_path = handle_to_path_hm;
    }
}

pub fn watchdogAdd(p_wd: *zga.ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
    if (p_wd.alloc) |alloc| {
        const path_as_lpcwstr: [:0]const u16 = try std.unicode.utf8ToUtf16LeAllocZ(alloc, path);
        defer alloc.free(path_as_lpcwstr);

        _ = flags; // unused currently

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
    } else return error.WATCHDOG_ALLOCATOR_NOT_DEFINED;
}

pub fn watchdogRemove(p_wd: *zga.ZGA_WATCHDOG, path: []const u8) !void {
    // removing from handle --> path hashmap
    if (p_wd.platform_vars.opt_hm_handle_to_path) |*p_hm_handle_to_path| {
        if (p_wd.platform_vars.opt_hm_path_to_handle == null) return error.HM_PATH_TO_HANDLE_NOT_INIT;
        const handle_to_remove: win32.HANDLE = p_wd.platform_vars.opt_hm_path_to_handle.?.get(path) orelse return error.HM_DOES_NOT_CONTAIN_PATH;

        if (p_hm_handle_to_path.contains(handle_to_remove) == true) { // checking if hashmap value exists
            if (p_hm_handle_to_path.remove(handle_to_remove) == false) return error.FAILED_TO_REMOVE_HANDLE_FROM_HM; // remove value from hashmap
        } else return error.PATH_DNE_IN_HM;

        win32.CloseHandle(handle_to_remove); // freeing memory associated with the handle
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;

    // removing from path --> handle hashmap
    if (p_wd.platform_vars.opt_hm_path_to_handle) |*p_hm_path_to_handle| {
        if (p_hm_path_to_handle.contains(path) == true) { // checking if hashmap value exists
            if (p_hm_path_to_handle.remove(path) == false) return error.FAILED_TO_REMOVE_PATH_FROM_HM; // remove value from hashmap
        } else return error.PATH_DNE_IN_HM;
    } else return error.HM_PATH_TO_HANDLE_NOT_INIT;
}

pub fn watchdogRead(p_wd: *zga.ZGA_WATCHDOG) !void {
    _ = p_wd;
}

pub fn watchdogDeinit(p_wd: *zga.ZGA_WATCHDOG) !void {
    _ = p_wd;
}

///////////////////////
// PRIVATE FUNCTIONS //
///////////////////////

