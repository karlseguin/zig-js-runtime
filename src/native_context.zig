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

const api = @import("api.zig");
const refl = @import("reflect.zig");
const Loop = api.Loop;

pub fn NativeContext(comptime config: anytype) type {
    return struct {
        loop: *Loop,
        allocator: Allocator,

        // App-specific context.
        app_context: config.AppContext,

        // only loaded once we have an Engine.Env ready
        // a bit of a chicken and egg thing with Context and Engine.Env
        _js_types: [config.app_types.len]usize,

        _js_objects: std.AutoHashMapUnmanaged(usize, usize),

        // Map references all objects created in both JS and Native world
        // either from JS through a constructor template call or from Native in
        // an addObject call
        //  - key is the adress of the object (as an int) it will be store on the JS object as an internal field
        //  - value is the index of API
        _native_objects: std.AutoHashMapUnmanaged(usize, usize),

        const Self = @This();

        pub fn init(allocator: Allocator, loop: *Loop, app_context: config.AppContext) Self {
            return .{
                .loop = loop,
                ._js_types = undefined,
                ._js_objects = .{},
                ._native_objects = .{},
                .allocator = allocator,
                .app_context = app_context,
            };
        }

        pub fn deinit(self: *Self) void {
            self._js_objects.deinit(self.allocator);
            self._native_objects.deinit(self.allocator);
        }

        pub fn stop(self: *Self) void {
            self._js_objects.clearAndFree(self.allocator);
            self._native_objects.clearAndFree(self.allocator);
        }

        pub fn getType(self: *const Self, comptime T: type, index: usize) *T {
            const t = self._js_types[index];
            return @as(*T, @ptrFromInt(t));
        }

        pub fn putNativeObject(self: *Self, ptr: usize, index: usize) !void {
            try self._native_objects.put(self.allocator, ptr, index);
        }

        pub fn putJsObject(self: *Self, native_ref: usize, js_ref: usize) !void {
            try self._js_objects.put(self.allocator, native_ref, js_ref);
        }
    };
}
