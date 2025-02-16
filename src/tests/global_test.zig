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

const public = @import("../api.zig");
const tests = public.test_utils;

const js_config = public.Config(.{
    GlobalParent,
    Global,
}, void);

const GlobalParent = struct {
    pub fn _parent(_: GlobalParent) bool {
        return true;
    }
};

pub const Global = struct {
    pub const prototype = *GlobalParent;
    pub const global_type = true;

    proto: GlobalParent = .{},

    pub fn _self(_: Global) bool {
        return true;
    }
};

// exec tests
test "integration: global" {
    var buf: [1024 * 4]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var runner = try tests.CaseRunner(js_config).init(fba.allocator(), {});
    defer runner.deinit();

    // global
    const global = Global{};
    var env = try runner.env();
    try env.bindGlobal(global);
    try env.attachObject(try env.getGlobal(), "global", null);

    var globals = [_]tests.Case{
        .{ .src = "Global.name", .ex = "Global" },
        .{ .src = "GlobalParent.name", .ex = "GlobalParent" },
        .{ .src = "self()", .ex = "true" },
        .{ .src = "parent()", .ex = "true" },
        .{ .src = "global.self()", .ex = "true" },
        .{ .src = "global.parent()", .ex = "true" },
        .{ .src = "global.foo = () => true; foo()", .ex = "true" },
        .{ .src = "bar = () => true; global.bar()", .ex = "true" },
    };
    try runner.run(&globals);
}
