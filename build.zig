// const std = @import("std");

// pub fn build(b: *std.Build) void {
//     const target = b.standardTargetOptions(.{});
//     const optimise = b.standardOptimizeOption(.{});

//     const exe = b.addExecutable(.{
//         .name = "Ziggatch",
//         .root_source_file = b.path("src/ziggatch.zig"),
//         .target = target,
//         .optimize = optimise,
//     });
//     b.installArtifact(exe);
// }