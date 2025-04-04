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

const jsruntime = @import("../api.zig");

const u64Num = jsruntime.u64Num;
const Callback = jsruntime.Callback;
const CallbackSync = jsruntime.CallbackSync;
const CallbackArg = jsruntime.CallbackArg;

const tests = jsruntime.test_utils;

pub const OtherCbk = struct {
    val: u8,

    pub fn get_val(self: OtherCbk) u8 {
        return self.val;
    }
};

pub const Window = struct {

    // store a map between internal timeouts ids and pointers to uint.
    // the maximum number of possible timeouts is fixed.
    timeoutid: u32 = 0,
    timeoutids: [10]u64 = undefined,

    pub fn constructor() Window {
        return Window{};
    }

    pub fn _cbkSyncWithoutArg(_: Window, _: CallbackSync) void {
        tests.sleep(1 * std.time.ns_per_ms);
    }

    pub fn _cbkSyncWithArg(_: Window, _: CallbackSync, _: CallbackArg) void {
        tests.sleep(1 * std.time.ns_per_ms);
    }

    pub fn _cbkAsync(
        self: *Window,
        loop: *jsruntime.Loop,
        callback: Callback,
        milliseconds: u32,
    ) !u32 {
        const n: u63 = @intCast(milliseconds);
        const id = try loop.timeout(n * std.time.ns_per_ms, callback);

        defer self.timeoutid += 1;
        self.timeoutids[self.timeoutid] = id;

        return self.timeoutid;
    }

    pub fn _cbkAsyncWithJSArg(
        self: *Window,
        loop: *jsruntime.Loop,
        callback: Callback,
        milliseconds: u32,
        _: CallbackArg,
    ) !u32 {
        const n: u63 = @intCast(milliseconds);
        const id = try loop.timeout(n * std.time.ns_per_ms, callback);

        defer self.timeoutid += 1;
        self.timeoutids[self.timeoutid] = id;

        return self.timeoutid;
    }

    pub fn _cancel(self: Window, loop: *jsruntime.Loop, id: u32) !void {
        if (id >= self.timeoutid) return;
        try loop.cancel(self.timeoutids[id], null);
    }

    pub fn _cbkAsyncWithNatArg(_: Window, callback: Callback) !void {
        const other = OtherCbk{ .val = 5 };
        callback.call(.{other}) catch {};
        // ignore the error to let the JS msg
    }

    pub fn get_cbk(_: Window) void {}

    pub fn set_cbk(_: *Window, callback: Callback) !void {
        callback.call(.{}) catch {};
    }

    pub fn deinit(_: *Window, _: std.mem.Allocator) void {}
};

pub const Types = .{
    OtherCbk,
    Window,
};

// exec tests
pub fn exec(
    _: std.mem.Allocator,
    js_env: *jsruntime.Env,
) anyerror!void {

    // start JS env
    try js_env.start();
    defer js_env.stop();

    // constructor
    var case_cstr = [_]tests.Case{
        .{ .src = "let window = new Window();", .ex = "undefined" },
    };
    try tests.checkCases(js_env, &case_cstr);

    // cbkSyncWithoutArg
    var cases_cbk_sync_without_arg = [_]tests.Case{
        // traditional anonymous function
        .{
            .src =
            \\let n = 1;
            \\function f() {n++};
            \\window.cbkSyncWithoutArg(f);
            ,
            .ex = "undefined",
        },
        .{ .src = "n;", .ex = "2" },
        // arrow function
        .{
            .src =
            \\let m = 1;
            \\window.cbkSyncWithoutArg(() => m++);
            ,
            .ex = "undefined",
        },
        .{ .src = "m;", .ex = "2" },
    };
    try tests.checkCases(js_env, &cases_cbk_sync_without_arg);

    // cbkSyncWithArg
    var cases_cbk_sync_with_arg = [_]tests.Case{
        // traditional anonymous function
        .{
            .src =
            \\let x = 1;
            \\function f(a) {x = x + a};
            \\window.cbkSyncWithArg(f, 2);
            ,
            .ex = "undefined",
        },
        .{ .src = "x;", .ex = "3" },
        // arrow function
        .{
            .src =
            \\let y = 1;
            \\window.cbkSyncWithArg((a) => y = y + a, 2);
            ,
            .ex = "undefined",
        },
        .{ .src = "y;", .ex = "3" },
    };
    try tests.checkCases(js_env, &cases_cbk_sync_with_arg);

    // cbkAsync
    var cases_cbk_async = [_]tests.Case{
        // traditional anonymous function
        .{
            .src =
            \\let o = 1;
            \\function f() {
            \\o++;
            \\if (o != 2) {throw Error('cases_cbk_async error: o is not equal to 2');}
            \\};
            \\window.cbkAsync(f, 100); // 0.1 second
            ,
            .ex = "0",
        },
        // arrow functional
        .{
            .src =
            \\let p = 1;
            \\window.cbkAsync(() => {
            \\p++;
            \\if (p != 2) {throw Error('cases_cbk_async error: p is not equal to 2');}
            \\}, 100); // 0.1 second
            ,
            .ex = "1",
        },
    };
    try tests.checkCases(js_env, &cases_cbk_async);

    // cbkAsyncWithJSArg
    var cases_cbk_async_with_js_arg = [_]tests.Case{
        // traditional anonymous function
        .{
            .src =
            \\let i = 1;
            \\function f(a) {
            \\i = i + a;
            \\if (i != 3) {throw Error('i is not equal to 3');}
            \\};
            \\window.cbkAsyncWithJSArg(f, 100, 2); // 0.1 second
            ,
            .ex = "2",
        },
        // arrow functional
        .{
            .src =
            \\let j = 1;
            \\window.cbkAsyncWithJSArg((a) => {
            \\j = j + a;
            \\if (j != 3) {throw Error('j is not equal to 3');}
            \\}, 100, 2); // 0.1 second
            ,
            .ex = "3",
        },
    };
    try tests.checkCases(js_env, &cases_cbk_async_with_js_arg);

    // cbkAsyncWithNatArg
    var cases_cbk_async_with_nat_arg = [_]tests.Case{
        .{ .src = "let exp = 5", .ex = "undefined" },

        // traditional anonymous function
        .{
            .src =
            \\function f(other) {
            \\if (other.val != exp) {throw Error('other.val expected ' + exp + ', got ' + other.val);}
            \\};
            \\window.cbkAsyncWithNatArg(f);
            ,
            .ex = "undefined",
        },
        // arrow functional
        .{
            .src =
            \\window.cbkAsyncWithNatArg((other) => {
            \\if (other.val != exp) {throw Error('other.val expected ' + exp + ', got ' + other.val);}
            \\});
            ,
            .ex = "undefined",
        },
    };
    try tests.checkCases(js_env, &cases_cbk_async_with_nat_arg);

    // setter cbk
    var cases_cbk_setter_arg = [_]tests.Case{
        .{ .src = "let v = 0", .ex = "undefined" },
        .{ .src = "window.cbk =  () => {v++};", .ex = "() => {v++}" },
        .{ .src = "v", .ex = "1" },
    };
    try tests.checkCases(js_env, &cases_cbk_setter_arg);

    if (tests.isCancelAvailable()) {
        // cancel cbk
        var cases_cbk_cancel = [_]tests.Case{
            .{
                .src =
                \\let vv = 0;
                \\const id = window.cbkAsync(() => {vv += 1}, 100);
                \\window.cancel(id);
                ,
                .ex = "undefined",
            },
            .{ .src = "vv", .ex = "0" },
        };
        try tests.checkCases(js_env, &cases_cbk_cancel);
    }
}
