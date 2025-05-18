const std = @import("std");

pub fn build(b: *std.Build) void {
    b.reference_trace = 10;
    const target = b.standardTargetOptions(.{});
    const optimise = b.standardOptimizeOption(.{});

    // how to tie into build?
    const tsq = b.dependency("TSQ", .{
        .target = target,
        .optimize = optimise,
    }); 

    _ = b.addModule("ZGA", .{
        .root_source_file = b.path("./src/zga.zig"),
        .target = target,
        .optimize = optimise,
    });
}