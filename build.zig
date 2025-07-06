const std = @import("std");

pub fn build(b: *std.Build) !void {

    // ---------- Setup: Initialize General Purpose Allocator and Default Build Options ----------

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // defining default options
    b.reference_trace = 10;
    const def_target = b.standardTargetOptions(.{});
    const def_optimise = b.standardOptimizeOption(.{});

    // tying TSQ dependency to ZGA import in sub-projects
    const TSQ_dependency = b.dependency("TSQ", .{
        .target = def_target,
        .optimize = def_optimise,
    });
    const TSQ_module = TSQ_dependency.module("TSQ"); // grabbing TSQ module from build.zig.zon TSQ project build.zig

    // creating base ZGA module
    const ZGA_module = b.addModule("ZGA", .{
        .root_source_file = b.path("./src/zga.zig"),
        .target = def_target,
        .optimize = def_optimise,
    });
    ZGA_module.addImport("TSQ", TSQ_module);

    // ---------- Testing: Scan src/ directory for all .zig files and add test steps ----------
    // ---------- will run if `zig build test` is run from cmd                       ----------

    const test_build_step = b.step("test", "Run all tests.");
    const tests_build_step = b.step("tests", "Run all tests.");

    // open the "src" directory --> for checking available files
    var src_dir: std.fs.Dir = try std.fs.cwd().openDir(b.pathFromRoot("src"), .{
        .iterate = true,
    });
    defer src_dir.close();
    
    // Create an iterator to walk through all directory entries inside "src"
    var src_iter: std.fs.Dir.Iterator = src_dir.iterate();

    // Loop over each entry in the "src" directory
    while (try src_iter.next()) |entry| {
        if (entry.kind == .file) {
            if (std.mem.endsWith(u8, entry.name, ".zig")) {

                const src_relative_path: []const u8 = b.fmt("src/{s}", .{entry.name});
                const src_lazypath = b.path(src_relative_path);
                const test_name = std.fmt.allocPrint(alloc, "test_{s}", .{entry.name}) catch entry.name;
                defer alloc.free(test_name);

                var test_step = b.addTest(.{
                    .name = test_name,
                    .root_source_file = src_lazypath,
                });
                test_step.root_module.addImport("ZGA", ZGA_module);
                test_step.root_module.addImport("TSQ", TSQ_module);

                test_build_step.dependOn(&test_step.step); // adding test to fleet of tests
                tests_build_step.dependOn(&test_step.step); // adding test to fleet of tests
            }
        }
    }

    // ---------- Conditional Build: Build Example Executables if '-Dexamples' Option is Enabled ----------   
    const example_build_step = b.step("example", "Build all examples.");
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
            const path: []const u8= try std.fmt.allocPrint(alloc, "./examples/src/{s}", .{example_file.basename});
            defer alloc.free(path);
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
            example_build_step.dependOn(&curr_exe.step);
            example_build_step.dependOn(&curr_exe_install_step.step);
            examples_build_step.dependOn(&curr_exe.step);
            examples_build_step.dependOn(&curr_exe_install_step.step);
        }
    }
}