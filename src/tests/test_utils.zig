// Copyright 2023-2024 Lightpanda (Selecy SAS)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const std = @import("std");
const Allocator = std.mem.Allocator;

const public = @import("../api.zig");

pub fn CaseRunner(comptime config: type) type {
    return struct {
        allocator: Allocator,
        loop: public.Loop,
        app_context: config.AppContext,
        _env: ?*public.Env(config) = null,

        const Self = @This();

        pub fn init(allocator: Allocator, app_context: config.AppContext) !Self {
            var loop = try public.Loop.init(allocator);
            errdefer loop.deinit();

            return .{
                .loop = loop,
                .allocator = allocator,
                .app_context = app_context,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self._env) |e| {
                e.stop();
                e.deinit();
            }
            self.loop.deinit();
        }

        pub fn env(self: *Self) !*public.Env(config) {
            if (self._env == null) {
                self._env = try config.createEnv(self.allocator, &self.loop, self.app_context);
                try self._env.?.start();
            }
            return self._env.?;
        }

        pub fn run(self: *Self, cases: []const Case) !void {
            return checkCasesAlloc(self.allocator, try self.env(), cases);
        }
    };
}

fn isTypeError(expected: []const u8, msg: []const u8) bool {
    if (!std.mem.eql(u8, expected, "TypeError")) {
        return false;
    }
    if (std.mem.startsWith(u8, msg, "Uncaught TypeError: ")) {
        return true;
    }
    if (std.mem.startsWith(u8, msg, "TypeError: ")) {
        // TODO: why callback exception does not start with "Uncaught"?
        return true;
    }
    return false;
}

pub fn sleep(nanoseconds: u64) void {
    const s = nanoseconds / std.time.ns_per_s;
    const ns = nanoseconds % std.time.ns_per_s;
    std.posix.nanosleep(s, ns);
}

// result memory is owned by the caller
pub fn intToStr(alloc: std.mem.Allocator, nb: u8) []const u8 {
    return std.fmt.allocPrint(
        alloc,
        "{d}",
        .{nb},
    ) catch unreachable;
}

// engineOwnPropertiesDefault returns the number of own properties
// by default for a current Type
// result memory is owned by the caller
pub fn engineOwnPropertiesDefault() u8 {
    return switch (public.Engine.engine()) {
        .v8 => 5,
    };
}

var test_case: usize = 0;

fn caseError(src: []const u8, exp: []const u8, res: []const u8, stack: ?[]const u8) void {
    std.debug.print("\n\tcase: ", .{});
    std.debug.print("\t\t{s}\n", .{src});
    std.debug.print("\texpected: ", .{});
    std.debug.print("\t{s}\n", .{exp});
    std.debug.print("\tactual: ", .{});
    std.debug.print("\t{s}\n", .{res});
    if (stack != null) {
        std.debug.print("\tstack: \n{s}\n", .{stack.?});
    }
}

pub fn checkCasesAlloc(allocator: Allocator, env: anytype, cases: []const Case) !void {
    var has_error = false;

    var try_catch: public.TryCatch = undefined;
    try_catch.init(env);
    defer try_catch.deinit();

    var case_arena = std.heap.ArenaAllocator.init(allocator);
    const alloc = case_arena.allocator();
    defer case_arena.deinit();

    // cases
    for (cases, 0..) |case, i| {
        defer _ = case_arena.reset(.retain_capacity);
        test_case += 1;

        // prepare script execution
        const name = try std.fmt.allocPrint(alloc, "test_{d}.js", .{test_case});

        // run script error
        const res = env.execWait(case.src, name) catch |err| {

            // is it an intended error?
            const except = try try_catch.exception(alloc, env);
            if (except) |msg| {
                defer alloc.free(msg);
                if (isTypeError(case.ex, msg)) continue;
            }

            has_error = true;
            if (i == 0) {
                std.debug.print("\n", .{});
            }

            const expected = switch (err) {
                error.JSExec => case.ex,
                error.JSExecCallback => case.cbk_ex,
                else => return err,
            };
            if (try try_catch.stack(alloc, env)) |stack| {
                defer alloc.free(stack);
                caseError(case.src, expected, except.?, stack);
            }
            continue;
        };

        // check if result is expected
        const res_string = try res.toString(alloc, env);
        defer alloc.free(res_string);
        const equal = std.mem.eql(u8, case.ex, res_string);
        if (!equal) {
            has_error = true;
            if (i == 0) {
                std.debug.print("\n", .{});
            }
            caseError(case.src, case.ex, res_string, null);
        }
    }
    if (has_error) {
        std.debug.print("\n", .{});
        return error.NotEqual;
    }
}

pub fn isCancelAvailable() bool {
    return switch (@import("builtin").target.os.tag) {
        .macos, .tvos, .watchos, .ios => false,
        else => true,
    };
}

pub const Case = struct {
    src: []const u8,
    ex: []const u8,
    cbk_ex: []const u8 = "undefined",
};

// a shorthand function to run a script within a JS env
// with local TryCatch
// - on success, do nothing
// - on error, log error the JS result and JS stack if available
pub fn runScript(
    js_env: *public.Env,
    alloc: Allocator,
    script: []const u8,
    name: []const u8,
) !void {

    // local try catch
    var try_catch: public.TryCatch = undefined;
    try_catch.init(js_env.*);
    defer try_catch.deinit();

    // check result
    _ = js_env.execWait(script, name) catch |err| {
        if (try try_catch.exception(alloc, js_env.*)) |msg| {
            defer alloc.free(msg);
            std.log.err("script {s} error: {s}\n", .{ name, msg });
        }
        if (try try_catch.stack(alloc, js_env.*)) |msg| {
            defer alloc.free(msg);
            std.log.err("script {s} stack: {s}\n", .{ name, msg });
        }
        return err;
    };
}
