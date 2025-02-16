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
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

const v8 = @import("v8");

const refl = @import("../../reflect.zig");
const public = @import("../../api.zig");

pub const Callback = @import("callback.zig").Func;
pub const CallbackSync = @import("callback.zig").FuncSync;
pub const CallbackArg = @import("callback.zig").Arg;
pub const CallbackResult = @import("callback.zig").Result;

const Loop = public.Loop;

pub const Module = v8.Module;
pub const ModuleLoadFn = *const fn (ctx: *anyopaque, referrer: ?Module, specifier: []const u8) anyerror!Module;

const loadTPL = @import("generate.zig").loadTPL;
const setNativeObject = @import("generate.zig").setNativeObject;
const bindObjectNativeAndJS = @import("generate.zig").bindObjectNativeAndJS;
const NativeContext = @import("../../native_context.zig").NativeContext;
const getTpl = @import("generate.zig").getTpl;

const nativeToJS = @import("types_primitives.zig").nativeToJS;
const valueToUtf8 = @import("types_primitives.zig").valueToUtf8;

const log = std.log.scoped(.v8);

pub const TPL = struct {
    tpl: v8.FunctionTemplate,
    index: usize,
};

pub const Object = v8.Object;

pub fn engine() @import("../engine.zig").EngineType {
    return .v8;
}

var platform: ?v8.Platform = null;

pub fn init() void {
    platform = v8.Platform.initDefault(0, true);
    v8.initV8Platform(platform.?);
    v8.initV8();
}

pub fn deinit() void {
    if (platform) |p| {
        _ = v8.deinitV8();
        v8.deinitV8Platform();
        p.deinit();
    }
}

pub fn Env(comptime config: anytype) type {
    return struct {
        isolate: v8.Isolate,
        hscope: v8.HandleScope,
        globals: v8.FunctionTemplate,
        inspector: ?Inspector = null,
        isolate_params: v8.CreateParams,
        native_context: NativeContext(config),

        js_ctx: ?v8.Context = null,

        moduleLoad: ?struct {
            ctx: *anyopaque,
            func: ModuleLoadFn,
        } = null,

        const Self = @This();

        pub fn init(native_context: NativeContext(config)) Self {
            // params
            var params = v8.initCreateParams();
            params.array_buffer_allocator = v8.createDefaultArrayBufferAllocator();

            // isolate
            var isolate = v8.Isolate.init(&params);
            isolate.enter();

            // handle scope
            var hscope: v8.HandleScope = undefined;
            hscope.init(isolate);

            // ObjectTemplate for the global namespace
            const globals = v8.FunctionTemplate.initDefault(isolate);

            return .{
                .hscope = hscope,
                .isolate = isolate,
                .globals = globals,
                .isolate_params = params,
                .native_context = native_context,
            };
        }

        pub fn deinit(self: *Self) void {
            self.native_context.deinit();

            // v8 values
            // ---------

            // handle scope
            var hscope = self.hscope;
            hscope.deinit();

            // isolate
            var isolate = self.isolate;
            isolate.exit();
            isolate.deinit();

            // params
            v8.destroyArrayBufferAllocator(self.isolate_params.array_buffer_allocator.?);
            self.native_context.allocator.destroy(self);
        }

        pub fn setInspector(self: *Self, inspector: Inspector) void {
            self.inspector = inspector;
        }

        pub inline fn getInspector(self: Env) ?Inspector {
            return self.inspector;
        }

        pub fn setAppContext(self: *Self, app_context: config.AppContext) void {
            self.native_context.app_context = app_context;
        }

        // load user-defined Types into Javascript environement
        pub fn loadTypes(self: *Self) !void {
            const app_types = config.app_types;
            var tpls: [app_types.len]TPL = undefined;
            inline for (app_types, 0..) |T_refl, i| {
                var proto: ?TPL = null;
                if (T_refl.proto_index) |proto_index| {
                    proto = tpls[proto_index];
                }
                tpls[i] = try loadTPL(T_refl, config, self, proto);
            }


            for (tpls, &self.native_context._js_types) |tpl, *js_type| {
                js_type.* = @intFromPtr(tpl.tpl.handle);
            }
        }

        const envIdx = 1;

        // tov8Ctx saves the current env pointer into the v8 context.
        fn tov8Ctx(self: *Self) void {
            if (self.js_ctx == null) unreachable;
            self.js_ctx.?.getIsolate().setData(envIdx, self);
        }

        // fromv8Ctx extracts the current env pointer into the v8 context.
        fn fromv8Ctx(ctx: v8.Context) *Self {
            const env = ctx.getIsolate().getData(envIdx);
            if (env == null) unreachable;
            return @ptrCast(@alignCast(env));
        }

        // start a Javascript context
        pub fn start(self: *Self) anyerror!void {

            // context
            self.js_ctx = v8.Context.init(self.isolate, self.globals.getInstanceTemplate(), null);
            const js_ctx = self.js_ctx.?;
            js_ctx.enter();

            // TODO: ideally all this should disapear,
            // we shouldn't do anything at context startup time
            inline for (config.app_types, 0..) |T_refl, i| {

                // APIs prototype
                // set the prototype of each corresponding constructor Function
                // NOTE: this is required to inherit attributes at the Type level,
                // ie. static class attributes.
                // For static instance attributes we set them
                // on FunctionTemplate.PrototypeTemplate
                // TODO: is there a better way to do it at the Template level?
                // see https://github.com/Browsercore/jsruntime-lib/issues/128
                if (T_refl.proto_index) |proto_index| {
                    const cstr_tpl = getTpl(&self.native_context, i);
                    const proto_tpl = getTpl(&self.native_context, proto_index);
                    const cstr_obj = cstr_tpl.getFunction(js_ctx).toObject();
                    const proto_obj = proto_tpl.getFunction(js_ctx).toObject();
                    _ = cstr_obj.setPrototype(js_ctx, proto_obj);
                }

                // Custom exception
                // NOTE: there is no way in v8 to subclass the Error built-in type
                // TODO: this is an horrible hack
                if (comptime T_refl.isException()) {
                    const script = T_refl.name ++ ".prototype.__proto__ = Error.prototype";
                    _ = self.exec(script, "errorSubclass") catch {
                        // TODO: is there a reason to override the error?
                        return error.errorSubClass;
                    };
                }
            }

            // save the env into the context.
            self.tov8Ctx();
        }

        // stop a Javascript context
        pub fn stop(self: *Self) void {
            if (self.js_ctx == null) {
                return; // no-op
            }

            // JS context
            self.js_ctx.?.exit();
            self.js_ctx = null;

            // Native context
            self.native_context.stop();
        }

        pub fn getGlobal(self: *const Self) anyerror!Object {
            if (self.js_ctx == null) {
                return error.EnvNotStarted;
            }
            return self.js_ctx.?.getGlobal();
        }

        pub fn bindGlobal(self: *Self, obj: anytype) anyerror!void {
            const T_refl = comptime config.getType(@TypeOf(obj));
            if (!comptime T_refl.isGlobalType()) return error.notGlobalType;
            const T = T_refl.Self();

            // ensure Native object is a pointer
            var nat_obj_ptr: *T = undefined;

            if (comptime refl.isPointer(@TypeOf(obj))) {

                // Native object is a pointer of T
                // no need to create it in heap,
                // we assume it has been done already by the API
                // just assign pointer to Native object
                nat_obj_ptr = obj;
            } else {

                // Native object is a value of T
                // create a pointer in heap
                // (otherwise on the stack it will be delete when the function returns),
                // and assign pointer's dereference value to Native object
                nat_obj_ptr = try self.native_context.allocator.create(T);
                nat_obj_ptr.* = obj;
            }

            _ = try bindObjectNativeAndJS(
                T_refl,
                &self.native_context,
                nat_obj_ptr,
                self.js_ctx.?.getGlobal(),
                self.js_ctx.?,
                self.isolate,
            );
        }

        // add a Native object in the Javascript context
        pub fn addObject(self: *Self, obj: anytype, name: []const u8) anyerror!void {
            const js_ctx = self.js_ctx orelse return error.EnvNotStarted;

            // retrieve obj API
            const T_refl = comptime NativeContext.context.getType(@TypeOf(obj));

            const isolate = self.isolate;

            // bind Native and JS objects together
            const js_obj = try setNativeObject(
                T_refl,
                T_refl.value.underT(),
                &self.native_context,
                obj,
                null,
                isolate,
                js_ctx,
            );

            // set JS object on target's key
            const key = v8.String.initUtf8(isolate, name);
            if (!js_ctx.getGlobal().setValue(js_ctx, key, js_obj)) {
                return error.CreateV8Object;
            }
        }

        pub fn attachObject(self: *const Self, obj: Object, name: []const u8, to_obj: ?Object) anyerror!void {
            if (self.js_ctx == null) {
                return error.EnvNotStarted;
            }
            const key = v8.String.initUtf8(self.isolate, name);
            // attach to globals if to_obj is not specified
            const to = to_obj orelse try self.getGlobal();
            const res = to.setValue(self.js_ctx.?, key, obj);
            if (!res) {
                return error.AttachObject;
            }
        }

        // compile and run a JS script
        // It doesn't wait for callbacks execution
        pub fn exec(self: *const Self, script: []const u8, name: ?[]const u8) anyerror!JSValue(Self) {
            const isolate = self.isolate;
            const js_ctx = self.js_ctx orelse return error.EnvNotStarted;

            // compile
            var origin: ?v8.ScriptOrigin = undefined;
            if (name) |n| {
                const scr_name = v8.String.initUtf8(isolate, n);
                origin = v8.ScriptOrigin.initDefault(isolate, scr_name.toValue());
            }
            const scr_js = v8.String.initUtf8(isolate, script);
            const scr = v8.Script.compile(js_ctx, scr_js, origin) catch return error.JSCompile;

            // run
            const value = scr.run(js_ctx) catch return error.JSExec;
            return .{ .value = value };
        }

        pub fn setModuleLoadFn(self: *Self, ctx: *anyopaque, mlfn: ModuleLoadFn) !void {
            self.moduleLoad = .{
                .ctx = ctx,
                .func = mlfn,
            };
        }

        pub fn compileModule(self: *const Self, src: []const u8, name: []const u8) anyerror!Module {
            if (self.js_ctx == null) {
                return error.EnvNotStarted;
            }

            // compile
            const script_name = v8.String.initUtf8(self.isolate, name);
            const script_source = v8.String.initUtf8(self.isolate, src);

            const origin = v8.ScriptOrigin.init(
                self.isolate,
                script_name.toValue(),
                0, // resource_line_offset
                0, // resource_column_offset
                false, // resource_is_shared_cross_origin
                -1, // script_id
                null, // source_map_url
                false, // resource_is_opaque
                false, // is_wasm
                true, // is_module
                null, // host_defined_options
            );

            var script_comp_source: v8.ScriptCompilerSource = undefined;
            script_comp_source.init(script_source, origin, null);
            defer script_comp_source.deinit();

            return v8.ScriptCompiler.compileModule(
                self.isolate,
                &script_comp_source,
                .kNoCompileOptions,
                .kNoCacheNoReason,
            ) catch return error.JSCompile;
        }

        // compile and eval a JS module
        // It doesn't wait for callbacks execution
        pub fn module(self: *const Self, src: []const u8, name: []const u8) anyerror!JSValue(Self) {
            if (self.js_ctx == null) {
                return error.EnvNotStarted;
            }

            const m = try self.compileModule(src, name);

            // instantiate
            // TODO handle ResolveModuleCallback parameters to load module's
            // dependencies.
            const ok = m.instantiate(self.js_ctx.?, resolveModuleCallback) catch return error.JSExec;
            if (!ok) {
                return error.ModuleInstantiateErr;
            }

            // evaluate
            const value = m.evaluate(self.js_ctx.?) catch return error.JSExec;
            return .{ .value = value };
        }

        pub fn resolveModuleCallback(
            c_ctx: ?*const v8.C_Context,
            specifier: ?*const v8.C_String,
            import_attributes: ?*const v8.C_FixedArray,
            referrer: ?*const v8.C_Module,
        ) callconv(.C) ?*const v8.C_Module {
            _ = import_attributes;

            if (c_ctx == null) unreachable;
            const ctx = v8.Context{ .handle = c_ctx.? };
            const self = Self.fromv8Ctx(ctx);

            const ml = self.moduleLoad orelse unreachable; // if module load is missing, this is a program error.

            // TODO use a fixed allocator?
            const alloc = self.native_context.allocator;

            // build the specifier value.
            const specstr = valueToUtf8(
                alloc,
                v8.Value{ .handle = specifier.? },
                ctx.getIsolate(),
                ctx,
            ) catch |e| {
                log.err("resolveModuleCallback: get ref str: {any}", .{e});
                return null;
            };
            defer alloc.free(specstr);

            const refmod = if (referrer) |ref| v8.Module{ .handle = ref } else null;

            const m = ml.func(ml.ctx, refmod, specstr) catch |e| {
                log.err("resolveModuleCallback: load fn: {any}", .{e});
                return null;
            };
            return m.handle;
        }

        // wait I/O Loop until all JS callbacks are executed
        // This is a blocking operation.
        // Errors can be either:
        // - an error of the Loop (eg. IO kernel)
        // - an error of one of the JS callbacks
        // NOTE: the Loop does not stop when a JS callback throw an error
        // ie. all JS callbacks are executed
        // TODO: return at first error on a JS callback and let the caller
        // decide whether going forward or not
        pub fn wait(self: *const Self) anyerror!void {
            if (self.js_ctx == null) {
                return error.EnvNotStarted;
            }

            // run loop
            return self.native_context.loop.run(config);
        }

        // compile and run a JS script and wait for all callbacks (exec + wait)
        // This is a blocking operation.
        pub fn execWait(self: *const Self, script: []const u8, name: ?[]const u8) anyerror!JSValue(Self) {
            const res = try self.exec(script, name);
            try self.wait();
            return res;
        }

        pub fn v8Data(self: *const Self) v8.BigInt {
            const n: u64 = @intCast(@intFromPtr(&self.native_context));
            return self.isolate.initBigIntU64(n);
        }
    };
}

pub const JSObjectID = struct {
    id: usize,

    pub fn set(obj: v8.Object) JSObjectID {
        return .{ .id = obj.getIdentityHash() };
    }

    pub fn get(self: JSObjectID) usize {
        return self.id;
    }
};

pub const JSObject = struct {
    js_ctx: v8.Context,
    js_obj: v8.Object,
    native_context: *anyopaque,

    pub fn set(self: JSObject, comptime config: anytype, key: []const u8, value: anytype) !void {
        const TV = @TypeOf(value);
        const isolate = self.js_ctx.getIsolate();

        var js_value: v8.Value = undefined;
        if (comptime refl.isBuiltinType(TV)) {
            js_value = try nativeToJS(TV, value, isolate);
        } else if (@typeInfo(TV) == .Union) {
            // NOTE: inspired by std.meta.TagPayloadByName
            const activeTag = @tagName(std.meta.activeTag(value));
            inline for (std.meta.fields(TV)) |field| {
                if (std.mem.eql(u8, activeTag, field.name)) {
                    return self.set(config, key, @field(value, field.name));
                }
            }
        } else {
            const T_refl = comptime config.getType(TV);
            const native_context: *NativeContext(config) = @alignCast(@ptrCast(self.native_context));
            const js_obj = try setNativeObject(
                T_refl,
                T_refl.Self(),
                native_context,
                value,
                null,
                isolate,
                self.js_ctx,
            );
            js_value = js_obj.toValue();
        }
        const js_key = v8.String.initUtf8(isolate, key);
        if (!self.js_obj.setValue(self.js_ctx, js_key, js_value)) {
            return error.SetV8Object;
        }
    }
};

pub fn JSValue(comptime E: type) type {
    return struct {
        value: v8.Value,

        const Self = @This();

        // the caller needs to deinit the string returned
        pub fn toString(self: Self, alloc: Allocator, env: *const E) anyerror![]const u8 {
            return valueToUtf8(alloc, self.value, env.isolate, env.js_ctx.?);
        }

        pub fn typeOf(self: Self, env: *const E) anyerror!public.JSTypes {
            var buf: [20]u8 = undefined;
            const str = try self.value.typeOf(env.isolate);
            const len = str.lenUtf8(env.isolate);
            const s = buf[0..len];
            _ = str.writeUtf8(env.isolate, s);
            return std.meta.stringToEnum(public.JSTypes, s) orelse {
                log.err("JSValueTypeNotHandled: {s}", .{s});
                return error.JSValueTypeNotHandled;
            };
        }
    };
}

pub const TryCatch = struct {
    inner: v8.TryCatch,

    const Self = @This();

    pub fn init(self: *Self, env: anytype) void {
        self.inner.init(env.isolate);
    }

    pub fn hasCaught(self: Self) bool {
        return self.inner.hasCaught();
    }

    // the caller needs to deinit the string returned
    pub fn exception(self: Self, alloc: Allocator, env: anytype) anyerror!?[]const u8 {
        if (env.js_ctx == null) return error.EnvNotStarted;

        if (self.inner.getException()) |msg| {
            return try valueToUtf8(alloc, msg, env.isolate, env.js_ctx.?);
        }
        return null;
    }

    // the caller needs to deinit the string returned
    pub fn stack(self: Self, alloc: Allocator, env: anytype) anyerror!?[]const u8 {
        if (env.js_ctx == null) return error.EnvNotStarted;

        const stck = self.inner.getStackTrace(env.js_ctx.?);
        if (stck) |s| return try valueToUtf8(alloc, s, env.isolate, env.js_ctx.?);
        return null;
    }

    // a shorthand method to return either the entire stack message
    // or just the exception message
    // - in Debug mode return the stack if available
    // - otherwhise return the exception if available
    // the caller needs to deinit the string returned
    pub fn err(self: Self, alloc: Allocator, env: anytype) anyerror!?[]const u8 {
        if (builtin.mode == .Debug) {
            if (try self.stack(alloc, env)) |msg| return msg;
        }
        return try self.exception(alloc, env);
    }

    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }
};

// Inspector

pub const Inspector = struct {
    inner: *v8.Inspector,
    session: v8.InspectorSession,

    pub fn init(
        alloc: Allocator,
        env: anytype,
        ctx: *anyopaque,
        onResp: public.InspectorOnResponseFn,
        onEvent: public.InspectorOnEventFn,
    ) anyerror!Inspector {
        const inner = try alloc.create(v8.Inspector);
        const channel = v8.InspectorChannel.init(ctx, onResp, onEvent, env.isolate);
        const client = v8.InspectorClient.init();
        v8.Inspector.init(inner, client, channel, env.isolate);
        const session = inner.connect();
        return .{ .inner = inner, .session = session };
    }

    pub fn deinit(self: Inspector, alloc: Allocator) void {
        self.inner.deinit();
        alloc.destroy(self.inner);
    }

    // From CDP docs
    // https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#type-ExecutionContextDescription
    // ----
    // - name: Human readable name describing given context.
    // - origin: Execution context origin (ie. URL who initialised the request)
    // - auxData: Embedder-specific auxiliary data likely matching
    // {isDefault: boolean, type: 'default'|'isolated'|'worker', frameId: string}
    pub fn contextCreated(
        self: Inspector,
        env: anytype,
        name: []const u8,
        origin: []const u8,
        auxData: ?[]const u8,
    ) void {
        self.inner.contextCreated(env.js_ctx.?, name, origin, auxData);
    }

    // msg should be formatted for the Inspector protocol
    // for v8 it's the CDP protocol https://chromedevtools.github.io/devtools-protocol/
    // with only some domains being relevant (mainly Runtime and Debugger)
    pub fn send(self: Inspector, env: anytype, msg: []const u8) void {
        return self.session.dispatchProtocolMessage(env.isolate, msg);
    }
};
