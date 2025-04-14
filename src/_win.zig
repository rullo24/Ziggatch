const std = @import("std");
const win32 = std.os.windows;

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

const LPDWORD = *win32.DWORD;
const LPOVERLAPPED = *OVERLAPPED;
const LPOVERLAPPED_COMPLETION_ROUTINE = LpoverlappedCompletionRoutine;

pub extern "minwinbase" fn LpoverlappedCompletionRoutine(dwErrorCode: win32.DWORD,
                                                    dwNumberOfBytesTransfered: win32.DWORD,
                                                    lpOverlapped: LPOVERLAPPED) void;
pub extern "kernel32" fn ReadDirectoryChangesW(
                                            hDirectory: win32.HANDLE,
                                            lpBuffer: win32.LPVOID,
                                            nBufferLength: win32.DWORD,
                                            bWatchSubtree: win32.BOOL,
                                            dwNotifyFilter: win32.DWORD,
                                            lpBytesReturned: LPDWORD,
                                            lpOverlapped: LPOVERLAPPED,
                                            lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
                                            ) win32.BOOL;

