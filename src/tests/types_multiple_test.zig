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

const js_config = public.Config(.{ Windows, MacOS, Linux, Computer }, void);

const Windows = struct {
    const manufacturer = "Microsoft";

    pub fn get_manufacturer(_: Windows) []const u8 {
        return manufacturer;
    }
};

const MacOS = struct {
    const manufacturer = "Apple";

    pub fn get_manufacturer(_: MacOS) []const u8 {
        return manufacturer;
    }
};

const Linux = struct {
    const manufacturer = "Linux Foundation";

    pub fn get_manufacturer(_: Linux) []const u8 {
        return manufacturer;
    }
};

const OSTag = enum {
    windows,
    macos,
    linux,
};

const OS = union(OSTag) {
    windows: Windows,
    macos: MacOS,
    linux: Linux,
};

const Computer = struct {
    os: OS,

    pub fn constructor(os_name: []u8) Computer {
        var os: OS = undefined;
        if (std.mem.eql(u8, os_name, "macos")) {
            os = OS{ .macos = MacOS{} };
        } else if (std.mem.eql(u8, os_name, "linux")) {
            os = OS{ .linux = Linux{} };
        } else {
            os = OS{ .windows = Windows{} };
        }
        return .{ .os = os };
    }

    pub fn get_os(self: Computer) OS {
        return self.os;
    }
};

// exec tests
test "integration: multiple" {
    var buf: [1024 * 4]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var runner = try tests.CaseRunner(js_config).init(fba.allocator(), {});
    defer runner.deinit();

    var cases = [_]tests.Case{
        .{ .src = "let linux_computer = new Computer('linux');", .ex = "undefined" },
        .{ .src = "let os = linux_computer.os;", .ex = "undefined" },
        .{ .src = "os.manufacturer", .ex = "Linux Foundation" },
    };
    try runner.run(&cases);
}
