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

//////////////////////////
// TYPEDEF DECLARATIONS //
//////////////////////////

const LPDWORD = *win32.DWORD;
const LPOVERLAPPED = *OVERLAPPED;
const LPOVERLAPPED_COMPLETION_ROUTINE = LpoverlappedCompletionRoutine;

///////////////////////////
// WINDOWS API FUNCTIONS //
///////////////////////////

extern "minwinbase" fn LpoverlappedCompletionRoutine(dwErrorCode: win32.DWORD,
                                                    dwNumberOfBytesTransfered: win32.DWORD,
                                                    lpOverlapped: LPOVERLAPPED) void;

// returns 0 if ReadDirectoryChangesW fails
extern "kernel32" fn ReadDirectoryChangesW(
                                            hDirectory: win32.HANDLE,
                                            lpBuffer: win32.LPVOID,
                                            nBufferLength: win32.DWORD,
                                            bWatchSubtree: win32.BOOL,
                                            dwNotifyFilter: win32.DWORD,
                                            lpBytesReturned: LPDWORD,
                                            lpOverlapped: LPOVERLAPPED,
                                            lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
                                            ) win32.BOOL;

//////////////////////
// PUBLIC FUNCTIONS //
//////////////////////

pub fn watchdogInit(p_wd: *zga.ZGA_WATCHDOG) !void {
    _ = p_wd;
}

pub fn watchdogAdd(p_wd: *zga.ZGA_WATCHDOG, path: []const u8, flags: u32) !void {
    _ = p_wd;
    _ = path;
    _ = flags;
}

pub fn watchdogRemove(p_wd: *zga.ZGA_WATCHDOG, path: []const u8) !void {
    _ = p_wd;
    _ = path;
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

