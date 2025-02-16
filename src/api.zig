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

// ----------
// Public API
// ----------

// only imports, no implementation code

// Loader and Context
// ------------------

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const bench_allocator = @import("bench.zig").allocator;
pub const test_utils = @import("tests/test_utils.zig");

// JS types
// --------

pub const JSTypes = enum {
    object,
    function,
    string,
    number,
    boolean,
    bigint,
    null,
    undefined,
};

const types = @import("types.zig");
pub const i64Num = types.i64Num;
pub const u64Num = types.u64Num;

pub const Iterable = types.Iterable;
pub const Variadic = types.Variadic;

pub const IO = @import("loop.zig").IO;
pub const Loop = @import("loop.zig").SingleThreaded;
pub const Console = @import("console.zig").Console;

// JS engine
// ---------

const engine = @import("engines/engine.zig");

pub const JSValue = Engine.JSValue;
pub const JSObject = Engine.JSObject;
pub const JSObjectID = Engine.JSObjectID;

pub const Callback = Engine.Callback;
pub const CallbackSync = Engine.CallbackSync;
pub const CallbackArg = Engine.CallbackArg;
pub const CallbackResult = Engine.CallbackResult;

pub const TryCatch = Engine.TryCatch;

pub const Inspector = Engine.Inspector;
pub const InspectorOnEventFn = *const fn (ctx: *anyopaque, msg: []const u8) void;
pub const InspectorOnResponseFn = *const fn (ctx: *anyopaque, call_id: u32, msg: []const u8) void;

pub const Module = Engine.Module;
pub const ModuleLoadFn = Engine.ModuleLoadFn;

pub const init = Engine.init;
pub const deinit = Engine.deinit;
pub const Engine = engine.Engine;
pub const EngineType = engine.EngineType;

// expose a slightly friendly name
pub const Env = Engine.Env;
pub const NativeContext = @import("native_context.zig").NativeContext;

pub fn Config(comptime interfaces: anytype, comptime AC: type) type {
    const reflect = @import("reflect.zig");

    const _app_types = reflect.typesToStruct(interfaces, AC) catch |err| {
        @compileError("Failed to generate interface types: " ++ @errorName(err));
    };

    return struct {
        const Self = @This();

        pub const app_types = _app_types;
        pub const AppContext = AC;

        pub fn createEnv(allocator: Allocator, loop: *Loop, app_context: AC) !*Env(Self) {
            var native_context = NativeContext(Self).init(allocator, loop, app_context);
            errdefer native_context.deinit();

            const env = try allocator.create(Env(Self));
            errdefer allocator.destroy(env);

            env.* = Env(Self).init(native_context);
            try env.loadTypes();
            return env;
        }

        pub fn getObject(comptime T: type, native_objects: anytype, ptr: anytype) !*T {
            // use the object pointer (key) to retrieve the API index (value) in the map
            const ptr_aligned: *align(@alignOf(usize)) anyopaque = @alignCast(ptr);
            const key: *usize = @ptrCast(ptr_aligned);
            const T_index = native_objects.get(key.*);

            if (T_index == null) {
                return error.NullReference;
            }

            // get the API corresponding to the API index
            // TODO: more efficient sorting?
            inline for (app_types) |T_refl| {
                if (T_refl.index == T_index.?) {
                    if (!T_refl.isEmpty()) { // stage1: condition is needed for empty structs
                        // go through the "proto" object chain
                        // to retrieve the good object corresponding to T
                        const target_ptr: *T_refl.Self() = @ptrFromInt(key.*);
                        return try getRealObject(T, target_ptr);
                    }
                }
            }
            return error.Reference;
        }

        pub fn getType(comptime T: type) reflect.Struct {
            std.debug.assert(@inComptime());
            for (app_types) |t| {
                if (T == t.Self() or T == *t.Self()) {
                    return t;
                }
            }
            @compileError("NativeTypeNotHandled: " ++ @typeName(T));
        }

        pub fn variadic(comptime T: type) !?reflect.Type {
            return reflect.Type.variadic(T, app_types, AppContext);
        }
    };
}

fn getRealObject(comptime T: type, target_ptr: anytype) !*T {
    const T_target = @TypeOf(target_ptr.*);
    if (T_target == T) {
        return target_ptr;
    }
    if (@hasField(T_target, "proto")) {
        // here we retun the "right" pointer: &(field(...))
        // ie. the direct pointer to the field
        // and not a pointer to a new const/var holding the field

        // TODO: and what if we have more than 2 types in the chain?
        return getRealObject(T, &(@field(target_ptr, "proto")));
    }
    return error.Reference;
}

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("tests/cbk_test.zig"));
    std.testing.refAllDecls(@import("tests/app_context_test.zig"));
    std.testing.refAllDecls(@import("tests/global_test.zig"));
    std.testing.refAllDecls(@import("tests/proto_test.zig"));
    std.testing.refAllDecls(@import("tests/types_complex_test.zig"));
    std.testing.refAllDecls(@import("tests/types_multiple_test.zig"));
    std.testing.refAllDecls(@import("tests/types_native_test.zig"));
    std.testing.refAllDecls(@import("tests/types_object_test.zig"));
    std.testing.refAllDecls(@import("tests/types_primitives_test.zig"));
}
