const std = @import("std");
const win32 = std.os.windows;
const _win = @import("_win.zig");

/////////////////////////
// STRUCT DECLARATIONS //
/////////////////////////
pub const EVENT = struct {
    name: []const u8,
    op: u32,
    prev_name: []const u8,
};

pub const WATCHDOG = struct {
    // backend: BACKEND,
    // event_queue: ,
    // error_queue: ,

    pub fn close() !void {
        // free mem for all subcomponents
    }
};

//////////////////////////////////
// PUBLIC FUNCTION DECLARATIONS //
//////////////////////////////////

pub fn createWatchdog() !WATCHDOG {
    // create thread-safe queues for events & errors
    // create backend object (so new backends are easy additions)
    // create watcher object --> use thread-safe queue and backend object
}

pub fn createAsyncWatchdog(func: *const fn, p_args: *anyopaque) !void {

}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////