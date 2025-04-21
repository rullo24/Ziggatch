const std = @import("std");
const win32 = std.os.windows;
const _win = @import("_win.zig");

///////////////////////////////////////
// MAGIC NUMBER (CONST) DECLARATIONS //
///////////////////////////////////////
const CREATE_OP: u8 = 0x01;
const WRITE_OP: u8 = 0x02;
const REMOVE_OP: u8 = 0x03;
const RENAME_OP: u8 = 0x04;

////////////////////////////////
// PUBLIC STRUCT DECLARATIONS //
////////////////////////////////

// obj to be used for abstracted O/S implementation differences
const BACKEND = struct {

};

// thread-safe queue for storing filesystem notifications/events
const EVENT_QUEUE = struct {

};

// thread-safe queue for storing errors
const ERROR_QUEUE = struct {

};

// represents a change to filesystem
pub const EVENT = struct {
    name: []const u8,
    op: u32,
    prev_name: []const u8,
};

// object used for concurrently capturing file changes
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

pub fn createWatchdog(b: BACKEND, evq: EVENT_QUEUE, erq: ERR_QUEUE) !WATCHDOG {
    // create thread-safe queues for events & errors
    // create backend object (so new backends are easy additions)
    // create watcher object --> use thread-safe queue and backend object
}

///////////////////////////////////
// PRIVATE FUNCTION DECLARATIONS //
///////////////////////////////////