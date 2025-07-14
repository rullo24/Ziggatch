const std = @import("std");

pub fn build(b: *std.Build) !void {

    // ---------- Setup: Initialize General Purpose Allocator and Default Build Options ----------

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // defining default options
    const def_target = b.standardTargetOptions(.{});
    const def_optimise = b.standardOptimizeOption(.{});

    // creating base ZGA module
    const ZGA_module = b.addModule("ZGA", .{
        .root_source_file = b.path("./src/zga.zig"),
        .target = def_target,
        .optimize = def_optimise,
    });

    // ---------- Testing: Scan src/ directory for all .zig files and add test steps ----------
    // ---------- will run if `zig build test` is run from cmd                       ----------

    const test_build_step = b.step("test", "Run all tests.");

    // zga.zig testing
    const zga_src_lazypath = b.path("./src/zga.zig");
    const zga_test_step = b.addTest(.{
        // .name = "ZGA_TEST",
        .root_source_file = zga_src_lazypath,
        .target = def_target,
        .optimize = def_optimise,
        .strip = false, // allow stderr print to console
        .error_tracing = true,
    });
    const run_zga_tests = b.addRunArtifact(zga_test_step);
    test_build_step.dependOn(&run_zga_tests.step); // adding test to fleet of tests

    // _inotify.zig testing
    if (def_target.result.os.tag == .linux) {
        const inotify_src_lazypath = b.path("./src/_inotify.zig");
        var inotify_test_step = b.addTest(.{
            .root_source_file = inotify_src_lazypath,
            .target = def_target,
            .optimize = def_optimise,
            .strip = false, // allow stderr print to console
            .error_tracing = true,
        });
        inotify_test_step.stack_size = 1024 * 1024 * 32; // 32MB stack size
        inotify_test_step.root_module.addImport("ZGA", ZGA_module);
        const run_inotify_tests = b.addRunArtifact(inotify_test_step);
        test_build_step.dependOn(&run_inotify_tests.step); // adding test to fleet of tests
    }

    // _win.zig testing
    if (def_target.result.os.tag == .windows) {
        const win_src_lazypath = b.path("./src/_win.zig");
        var win_test_step = b.addTest(.{
            .root_source_file = win_src_lazypath,
            .target = def_target,
            .optimize = def_optimise,
            .strip = false, // allow stderr print to console
            .error_tracing = true,
        });
        win_test_step.stack_size = 1024 * 1024 * 32; // 32MB stack size
        win_test_step.root_module.addImport("ZGA", ZGA_module);
        const run_win_tests = b.addRunArtifact(win_test_step);
        test_build_step.dependOn(&run_win_tests.step); // adding test to fleet of tests
    }

    // ---------- Conditional Build: Build Example Executables if '-Dexamples' Option is Enabled ----------   
    const examples_build_step = b.step("examples", "Build all examples.");

    // if (should_build_examples == true) { 
    const example_src_dir_path: []const u8 = b.pathFromRoot("examples/src");
    var example_dir = try std.fs.openDirAbsolute(example_src_dir_path, .{ .iterate = true }); // opening a directory obj
    defer example_dir.close(); // close file on build function end
    var example_dir_walker = try example_dir.walk(alloc); // creating a directory walker obj
    defer example_dir_walker.deinit(); // free memory on function close

    // iterate over each file
    while (try example_dir_walker.next()) |example_file| { 
        if (example_file.kind == .file) { // checking that the current file is a regular file

            // creating zig strings from NULL terminated ones
            const path: []const u8 = b.fmt("./examples/src/{s}", .{example_file.basename});
            const example_file_basename: []const u8 = std.fs.path.stem(example_file.basename);

            // grabbing tag names from build flags
            const arch_str: []const u8 = @tagName(def_target.result.cpu.arch);
            const os_str: []const u8 = @tagName(def_target.result.os.tag);
            const exe_name: []const u8 = b.fmt("{s}_{s}_{s}", .{example_file_basename, arch_str, os_str});

            // creating executables for each example
            const curr_exe = b.addExecutable(.{ 
                .name = exe_name,
                .root_source_file = b.path(path),
                .target = def_target,
                .optimize = def_optimise,
            });

            // linking libraries to and creating each executable
            curr_exe.root_module.addImport("ZGA", ZGA_module);
            const curr_exe_install_step = b.addInstallArtifact(curr_exe, .{}); // creating an artifact (exe) for each example

            // setting the executable install steps so that they only run if the "examples" step is defined in the zig build
            examples_build_step.dependOn(&curr_exe.step);
            examples_build_step.dependOn(&curr_exe_install_step.step);
        }
    }
}