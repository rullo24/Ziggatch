const std = @import("std");

pub fn build(b: *std.Build) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc: std.mem.Allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // defining default options
    b.reference_trace = 10;
    const def_target = b.standardTargetOptions(.{});
    const def_optimise = b.standardOptimizeOption(.{});

    // checking build flags
    const should_build_examples: bool = b.option(bool, "eg", "Will build ZGA examples.") orelse false;

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
    
    




    // building example executables
    
    



    // TO BE CHANGED AFTER DONE DEBUGGING (CURRENTLY should_build_examples set to opposite bool for easy building exes)






    if (should_build_examples != true) { 
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



                



                // for windows dev on linux

                const forced_target = b.resolveTargetQuery(.{
                    .os_tag = .windows,
                    .cpu_arch = def_target.result.cpu.arch,
                });




                // creating executables for each example
                const curr_exe = b.addExecutable(.{ 
                    .name = exe_name,
                    .root_source_file = b.path(path),
                    .target = forced_target,
                    .optimize = def_optimise,
                });

                // linking libraries to and creating each executable
                curr_exe.root_module.addImport("ZGA", ZGA_module);
                b.installArtifact(curr_exe); // creating an artifact (exe) for each example
            }
        }
    }
}