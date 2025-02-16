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
const v8 = @import("v8");

const Allocator = std.mem.Allocator;

const refl = @import("../../reflect.zig");
const NativeContext = @import("../../native_context.zig").NativeContext;

const public = @import("../../api.zig");
const Loop = public.Loop;

const cbk = @import("callback.zig");
const nativeToJS = @import("types_primitives.zig").nativeToJS;
const jsToNative = @import("types_primitives.zig").jsToNative;
const jsToObject = @import("types_primitives.zig").jsToObject;

const TPL = @import("v8.zig").TPL;
const JSObject = @import("v8.zig").JSObject;
const JSObjectID = @import("v8.zig").JSObjectID;

const LoadError = error{
    NoPrototypeTemplateProvided,
    WrongPrototypeTemplateProvided,
};

pub fn loadTPL(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
    env: anytype,
    proto_tpl: ?TPL,
) LoadError!TPL {
    // create a v8 FunctionTemplate for the T constructor function,
    // with the corresponding zig callback,
    // and attach it to the global namespace)
    const function = generateConstructor(T_refl, config);
    const template = v8.FunctionTemplate.initCallbackData(env.isolate, function, env.v8Data());
    const key = v8.String.initUtf8(env.isolate, T_refl.name);
    template.setClassName(key);
    env.globals.getInstanceTemplate().set(key.toName(), template, v8.PropertyAttribute.None);

    try loadFunctionTemplate(T_refl, config, env, template, proto_tpl);

    if (comptime T_refl.isGlobalType()) {
        try loadFunctionTemplate(T_refl, config, env, env.globals, proto_tpl);
    }

    // return the FunctionTemplate of the constructor
    return .{ .tpl = template, .index = T_refl.index };
}

fn loadFunctionTemplate(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
    env: anytype,
    tpl: v8.FunctionTemplate,
    proto_tpl: ?TPL,
) LoadError!void {

    // static attributes keys and values
    comptime var static_count: usize = undefined;

    if (T_refl.static_attrs_T) |attr_T| {
        static_count = @typeInfo(attr_T).Struct.fields.len;
    } else {
        static_count = 0;
    }

    var static_keys: [static_count]v8.Name = undefined;
    var static_values: [static_count]v8.Value = undefined;
    staticAttrsKeys(T_refl, &static_keys, env.isolate);
    staticAttrsValues(T_refl, &static_values, env.isolate);

    // set static attributes on the v8 FunctionTemplate
    setStaticAttrs(T_refl, tpl, &static_keys, &static_values);

    // set the optional prototype of the constructor
    if (comptime T_refl.proto_index != null) {
        if (proto_tpl == null) {
            return LoadError.NoPrototypeTemplateProvided;
        }
        if (T_refl.proto_index.? != proto_tpl.?.index) {
            return LoadError.WrongPrototypeTemplateProvided;
        }
        // at instance level, inherit from proto template
        // ie. an instance of the Child function has all properties
        // on Parent's instance template
        // ie. <Child>.prototype.__proto__ === <Parent>.prototype
        tpl.inherit(proto_tpl.?.tpl);
    }

    // NOTE: There is 2 different ObjectTemplate
    // attached to the FunctionTemplate of the constructor:
    // - The PrototypeTemplate which represents the template
    // of the protype of the constructor.
    // All getter/setter/methods must be set on it.
    // - The InstanceTemplate wich represents the template
    // of the instance created by the constructor.
    // This template holds the internal field count.

    // get the v8 InstanceTemplate attached to the constructor
    // and set 1 internal field to bind the counterpart zig object
    const object_template = tpl.getInstanceTemplate();
    if (!T_refl.isEmpty()) {
        // if the object is an empty struct (ie. a kind of container)
        // no need to keep its reference
        object_template.setInternalFieldCount(1);
    }

    // get the v8 Prototypetemplate attached to the constructor
    // to set getter/setter/methods
    const prototype = tpl.getPrototypeTemplate();

    // set static attributes on the v8 ObjectTemplate
    // so each instance will get them
    setStaticAttrs(T_refl, prototype, &static_keys, &static_values);

    loadObjectTemplate(T_refl, config, env, prototype);
}

fn loadObjectTemplate(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
    env: anytype,
    tpl: v8.ObjectTemplate,
) void {

    // the data we pass to and get from V8
    const data = env.v8Data();
    const isolate = env.isolate;
    // set getters for the v8 ObjectTemplate,
    // with the corresponding zig callbacks
    inline for (T_refl.getters) |getter| {
        const getter_func = generateGetter(T_refl, config, getter);
        var key: v8.Name = undefined;
        if (getter.symbol) |symbol| {
            key = switch (symbol) {
                .string_tag => v8.Symbol.getToStringTag(isolate),
                else => unreachable,
            }.toName();
        } else {
            key = v8.String.initUtf8(isolate, getter.js_name).toName();
        }

        if (getter.setter_index == null) {
            tpl.setGetterData(key, getter_func, data);
        } else {
            const setter = T_refl.setters[getter.setter_index.?];
            const setter_func = generateSetter(T_refl, config, setter);
            tpl.setGetterAndSetterData(key, getter_func, setter_func, data);
        }
    }

    // add string tag if not provided
    if (!T_refl.string_tag) {
        const key = v8.Symbol.getToStringTag(isolate).toName();
        tpl.setGetter(key, generateStringTag(T_refl.name));
    }

    // create a v8 FunctionTemplate for each T methods,
    // with the corresponding zig callbacks,
    // and attach them to the object template
    inline for (T_refl.methods) |method| {
        const func = generateMethod(T_refl, method, config);
        const func_tpl = v8.FunctionTemplate.initCallbackData(isolate, func, data);
        var key: v8.Name = undefined;
        if (method.symbol) |symbol| {
            key = switch (symbol) {
                .iterator => v8.Symbol.getIterator(isolate),
                else => unreachable,
            }.toName();
        } else {
            key = v8.String.initUtf8(isolate, method.js_name).toName();
        }
        tpl.set(key, func_tpl, v8.PropertyAttribute.None);
    }
}

// Utils functions
// ---------------

const JSError = error{
    InvalidArgument,
};

fn throwBasicError(msg: []const u8, isolate: v8.Isolate) v8.Value {
    const except_msg = v8.String.initUtf8(isolate, msg);
    const exception = v8.Exception.initError(except_msg);
    return isolate.throwException(exception);
}

fn throwError(
    comptime T_refl: refl.Struct,
    comptime func: refl.Func,
    comptime config: anytype,
    native_context: anytype,
    err: anyerror,
    isolate: v8.Isolate,
) v8.Value {
    // well known error.
    switch (err) {
        JSError.InvalidArgument => return throwTypeError("invalid argument", isolate),
        else => {},
    }
    const ret = func.return_type;

    // Is the returned Type a custom Exception error?
    // conditions:
    // - the return type must be an ErrorUnion
    // - the API must define a custom Exception
    // - the ErrorSet of the return type must be an error of Exception
    const except = comptime T_refl.exception(config.app_types);
    if (comptime ret.errorSet() == null or except == null) {
        return throwBasicError(@errorName(err), isolate);
    }
    if (!ret.isErrorException(except.?, err)) {
        return throwBasicError(@errorName(err), isolate);
    }

    // create custom error instance
    // TODO: by now the compiler is not able to see that we have ensure that at runtime
    // the error will be part of the ErrorSet of the custom exception.
    // So we have to use anyerror type here for now
    // and let the API implementation do the cast
    const obj = except.?.T.init(native_context.allocator, err, func.js_name) catch unreachable; // TODO
    const js_obj = setNativeObject(
        except.?,
        @TypeOf(obj),
        native_context,
        obj,
        null,
        isolate,
        isolate.getCurrentContext(),
    ) catch unreachable;

    // TODO: v8 does not throw a stack trace as Exception is not a prototype of Error
    // There is no way to change this with the current v8 public API

    // throw exeption
    return isolate.throwException(js_obj);
}

fn throwTypeError(msg: []const u8, isolate: v8.Isolate) v8.Value {
    const err = v8.String.initUtf8(isolate, msg);
    const exception = v8.Exception.initTypeError(err);
    return isolate.throwException(exception);
}

const not_enough_args = "{s}.{s}: At least {d} argument required, but only {d} passed";

// checkArgsLen of the JS call
// Return true if JS call provides enough arguments than defined natively.
// JS call is allowed to provide more arguments, they will be ignored.
// If JS call provides less arguments, throw a TypeError and return false.
fn checkArgsLen(
    comptime name: []const u8,
    comptime func: refl.Func,
    cbk_info: CallbackInfo,
    raw_value: ?*const v8.C_Value,
    isolate: v8.Isolate,
) bool {

    // check mandatory args
    var func_args_len: usize = func.args.len;
    if (func.first_optional_arg) |args_mandatory| {
        func_args_len = args_mandatory;
    }
    func_args_len -= func.index_offset;

    // OK
    const js_args_len = cbk_info.length(raw_value);
    if (js_args_len >= func_args_len) {
        // NOTE: using > to allow JS call to provide more arguments
        return true;
    }

    // throw a TypeError
    const args = .{
        name,
        func.js_name,
        func_args_len,
        js_args_len,
    };
    var buf: [100]u8 = undefined;
    const msg = std.fmt.bufPrint(buf[0..], not_enough_args, args) catch unreachable;
    const js_err = throwTypeError(msg, isolate);
    cbk_info.getReturnValue().set(js_err);
    return false;
}

fn getNativeArg(
    comptime arg_T: refl.Type,
    comptime config: anytype,
    native_context: anytype,
    js_value: v8.Value,
) !arg_T.T {
    var value: arg_T.T = undefined;

    // JS Null or Undefined value
    if (js_value.isNull() or js_value.isUndefined()) {
        // if Native optional type return null
        if (comptime arg_T.underOpt() != null) {
            return null;
        }
    }

    if (!js_value.isObject()) return JSError.InvalidArgument;

    const T_refl = config.app_types[arg_T.T_refl_index.?];

    // JS object
    const ptr = try getNativeObject(T_refl, config, native_context, js_value.castTo(v8.Object));
    if (comptime arg_T.underPtr() != null) {
        value = ptr;
    } else {
        value = ptr.*;
    }
    return value;
}

fn getArg(
    comptime T_refl: refl.Struct,
    comptime arg_T: refl.Type,
    comptime config: anytype,
    native_context: anytype,
    this: v8.Object,
    js_val: ?v8.Value,
    isolate: v8.Isolate,
    js_ctx: v8.Context,
) !arg_T.T {
    var value: arg_T.T = undefined;
    const allocator = native_context.allocator;

    if (comptime arg_T.isNative()) {

        // native types
        value = try getNativeArg(
            arg_T,
            config,
            native_context,
            js_val.?,
        );
    } else if (arg_T.nested_index) |index| {

        // nested types (ie. JS anonymous objects)
        value = jsToObject(
            T_refl.nested[index],
            arg_T.T,
            allocator,
            js_val.?,
            isolate,
            js_ctx,
        ) catch unreachable;
    } else {
        // builtin and internal types
        value = switch (arg_T.T) {
            *Loop => native_context.loop,
            Allocator => allocator,
            config.AppContext => native_context.app_context,
            cbk.Func, cbk.FuncSync, cbk.Arg => unreachable,
            JSObject => JSObject{
                .js_obj = this,
                .js_ctx = js_ctx,
                .native_context = native_context,
            },
            JSObjectID => JSObjectID.set(js_val.?.castTo(v8.Object)),
            else => jsToNative(
                arg_T.T,
                allocator,
                js_val.?,
                isolate,
                js_ctx,
            ) catch unreachable,
        };
    }

    return value;
}

pub const CallbackInfo = union(enum) {
    func_cbk: v8.FunctionCallbackInfo,
    prop_cbk: v8.PropertyCallbackInfo,

    fn getIsolate(self: CallbackInfo) v8.Isolate {
        return switch (self) {
            .func_cbk => |f| f.getIsolate(),
            .prop_cbk => |p| p.getIsolate(),
        };
    }

    fn length(self: CallbackInfo, raw_value: ?*const v8.C_Value) u32 {
        return switch (self) {
            .func_cbk => |f| f.length(),
            .prop_cbk => if (raw_value == null) 0 else 1,
        };
    }

    fn getThis(self: CallbackInfo) v8.Object {
        return switch (self) {
            .func_cbk => |f| f.getThis(),
            .prop_cbk => |p| p.getThis(),
        };
    }

    fn getData(self: CallbackInfo) v8.Value {
        return switch (self) {
            .func_cbk => |f| f.getData(),
            .prop_cbk => |c| c.getData(),
        };
    }

    pub fn getArg(
        self: CallbackInfo,
        raw_value: ?*const v8.C_Value,
        index: usize,
        index_offset: usize,
    ) ?v8.Value {
        const i = @as(i8, @intCast(index)) - @as(i8, @intCast(index_offset));
        if (i < 0) return null;
        switch (self) {
            .func_cbk => |f| return f.getArg(@as(u32, @intCast(i))),
            .prop_cbk => {
                if (raw_value) |val| {
                    return .{ .handle = val };
                }
                return null;
            },
        }
    }

    fn getReturnValue(self: CallbackInfo) v8.ReturnValue {
        return switch (self) {
            .func_cbk => |f| f.getReturnValue(),
            .prop_cbk => |p| p.getReturnValue(),
        };
    }
};

// This function takes either a v8.FunctionCallbackInfo
// or a v8.Propertycallbackinfo
// in case of a setter raw_value is also required
fn getArgs(
    comptime T_refl: refl.Struct,
    comptime func: refl.Func,
    comptime config: anytype,
    native_context: anytype,
    cbk_info: CallbackInfo,
    raw_value: ?*const v8.C_Value,
    isolate: v8.Isolate,
    js_ctx: v8.Context,
) !func.args_T {
    var args: func.args_T = undefined;

    const allocator = native_context.allocator;
    const js_args_nb = cbk_info.length(raw_value);

    // iter on function expected arguments
    inline for (func.args, 0..) |arg, i| {

        // do not set empty arg
        if (@sizeOf(arg.T) == 0) {
            continue;
        }

        comptime var arg_real: refl.Type = undefined;

        comptime {
            if (try config.variadic(arg.underT())) |arg_v| {
                arg_real = arg_v;
            } else {
                arg_real = arg;
            }
        }

        var value: arg.T = undefined;

        if (arg.T == arg_real.T) {

            // non-variadic arg
            value = switch (arg.T) {
                cbk.Func => try cbk.Func.init(
                    func,
                    native_context,
                    raw_value,
                    cbk_info,
                    isolate,
                ),
                cbk.FuncSync => try cbk.FuncSync.init(
                    func,
                    native_context,
                    raw_value,
                    cbk_info,
                    isolate,
                ),
                cbk.Arg => cbk.Arg{}, // stage1: we need type

                // normal cases
                else => blk: {
                    break :blk try getArg(
                        T_refl,
                        arg_real,
                        config,
                        native_context,
                        cbk_info.getThis(),
                        cbk_info.getArg(raw_value, i, func.index_offset),
                        isolate,
                        js_ctx,
                    );
                },
            };
        } else {

            // variadic arg
            // take all trailing JS arg as variadic members
            const rest_nb = js_args_nb - i + func.index_offset;
            const slice = try allocator.alloc(arg_real.T, rest_nb);
            var iter: usize = 0;
            while (iter < rest_nb) {
                const slice_value = try getArg(
                    T_refl,
                    arg_real,
                    config,
                    native_context,
                    cbk_info.getThis(),
                    cbk_info.getArg(raw_value, iter + i, func.index_offset),
                    isolate,
                    js_ctx,
                );
                slice[iter] = slice_value;
                iter += 1;
            }
            value = .{ .slice = slice };
        }

        // set argument
        @field(args, arg.name.?) = value;
    }

    return args;
}

fn freeArgs(
    comptime func: refl.Func,
    comptime config: anytype,
    allocator: Allocator,
    obj: anytype
) !void {
    inline for (func.args) |arg_T| {
        const underT = comptime arg_T.underT();

        // free char slices
        // the API functions will be responsible of copying the slice
        // in their implementations if they want to keep it afterwards
        if (underT == []u8 or underT == []const u8) {
            const val = @field(obj, arg_T.name.?);
            if (comptime arg_T.underOpt() != null) {
                // free only if val is non-null
                if (val) |v| {
                    allocator.free(v);
                }
            } else {
                allocator.free(val);
            }
        }

        // free varidadic slices
        if (try refl.Type.variadic(underT, null, config.AppContext) != null) {
            const val = @field(obj, arg_T.name.?).?;
            // NOTE: variadic are optional by design
            allocator.free(@field(val, "slice"));
        }
    }
}

const PersistentObject = v8.Persistent(v8.Object);

fn bindObjectNativeToJS(
    comptime T_refl: refl.Struct,
    native_context: anytype,
    nat_obj: anytype,
    js_obj: v8.Object,
    isolate: v8.Isolate,
) !v8.Object {

    // make this object persistent
    // otherwise it's a local handle which can garbage-collected when
    // the JS object is not reachable anymore
    // TODO: add a GC finalizer to remove the JS object reference
    // from the objects map
    const pers = PersistentObject.init(isolate, js_obj);
    const js_obj_pers = pers.castToObject();

    // bind the native object pointer to the JS object
    var ext: v8.External = undefined;
    if (comptime T_refl.is_mem_guarantied()) {
        // store directly the object pointer
        ext = v8.External.init(isolate, nat_obj);
    } else {
        const allocator = native_context.allocator;
        // use the refs mechanism
        const int_ptr = try allocator.create(usize);
        int_ptr.* = @intFromPtr(nat_obj);
        ext = v8.External.init(isolate, int_ptr);
        try native_context.putNativeObject(int_ptr.*, T_refl.index);
    }
    js_obj_pers.setInternalField(0, ext);
    return js_obj_pers;
}

fn bindObjectJSToNative(
    native_context: anytype,
    nat_obj: anytype,
    js_obj: v8.Object,
) !void {
    const nat_obj_ref = @intFromPtr(nat_obj);
    const js_obj_ref = @intFromPtr(js_obj.handle);
    return native_context.putJsObject(nat_obj_ref, js_obj_ref);
}

pub fn bindObjectNativeAndJS(
    comptime T_refl: refl.Struct,
    native_context: anytype,
    nat_obj: anytype,
    js_obj: v8.Object,
    js_ctx: v8.Context,
    isolate: v8.Isolate,
) !v8.Object {

    // if the native object is an empty struct (ie. a kind of container)
    // no need to keep it's reference
    if (T_refl.isEmpty()) {
        return js_obj;
    }

    // bind the Native object to the JS object
    const js_obj_binded = try bindObjectNativeToJS(
        T_refl,
        native_context,
        nat_obj,
        js_obj,
        isolate,
    );

    // bind the JS object to the Native object
    try bindObjectJSToNative(native_context, nat_obj, js_obj_binded);

    // call postAttach func
    if (comptime try refl.postAttachFunc(T_refl.T)) |piArgsT| {
        try postAttach(
            T_refl,
            piArgsT,
            native_context,
            nat_obj,
            js_obj_binded,
            js_ctx,
        );
    }
    return js_obj_binded;
}

pub fn getTpl(native_context: anytype, index: usize) v8.FunctionTemplate {
    const handle = native_context.getType(v8.C_FunctionTemplate, index);
    return .{ .handle = handle };
}

inline fn initJSObject(
    native_context: anytype,
    index: usize,
    js_ctx: v8.Context,
) v8.Object {
    const tpl = getTpl(native_context, index);
    return tpl.getInstanceTemplate().initInstance(js_ctx);
}

// getV8Object returns the existing v8.Object corresponding to the given native
// pointer from the native context.
pub fn getV8Object(native_context: anytype, nat_obj_ptr: anytype) !?v8.Object {
    // ensure Native object is a pointer
    if (comptime !refl.isPointer(@TypeOf(nat_obj_ptr))) return error.NotAPointer;

    const nat_obj_ref = @intFromPtr(nat_obj_ptr);
    const js_obj_ref = native_context._js_objects.get(nat_obj_ref) orelse return null;
    const js_obj_handle = @as(*v8.C_Object, @ptrFromInt(js_obj_ref));
    return .{ .handle = js_obj_handle };
}

pub fn setNativeObject(
    comptime T_refl: refl.Struct,
    comptime T: type,
    native_context: anytype,
    nat_obj: anytype,
    js_obj: ?v8.Object,
    isolate: v8.Isolate,
    js_ctx: v8.Context,
) !v8.Object {

    // ensure Native object is a pointer
    var nat_obj_ptr: *T = undefined;

    if (comptime refl.isPointer(@TypeOf(nat_obj))) {

        // Native object is a pointer of T
        // no need to create it in heap,
        // we assume it has been done already by the API
        // just assign pointer to Native object
        nat_obj_ptr = nat_obj;
    } else {

        // Native object is a value of T
        // create a pointer in heap
        // (otherwise on the stack it will be delete when the function returns),
        // and assign pointer's dereference value to Native object
        nat_obj_ptr = try native_context.allocator.create(T);
        nat_obj_ptr.* = nat_obj;
    }

    // should we create the JS object?
    var js_obj_under: v8.Object = undefined;
    if (js_obj) |o| {

        // JS object is already provided
        js_obj_under = o;
    } else if (!comptime refl.isPointer(@TypeOf(nat_obj))) {

        // Native object is a value, we need to return a new JS object
        // we can create it directly from its template
        js_obj_under = initJSObject(native_context, T_refl.index, js_ctx);
    } else {

        // JS object is not provided, check the objects map
        const nat_obj_ref = @intFromPtr(nat_obj_ptr);
        if (native_context._js_objects.get(nat_obj_ref)) |js_obj_ref| {

            // a JS object is already linked to the current Native object
            // return it
            const js_obj_handle = @as(*v8.C_Object, @ptrFromInt(js_obj_ref));
            js_obj_under = v8.Object{ .handle = js_obj_handle };
            return js_obj_under;
        } else {

            // no JS object is linked to the current Native object
            // let's create one from its template
            js_obj_under = initJSObject(native_context, T_refl.index, js_ctx);
        }
    }

    // bind Native and JS objects together
    return try bindObjectNativeAndJS(
        T_refl,
        native_context,
        nat_obj_ptr,
        js_obj_under,
        js_ctx,
        isolate,
    );
}

pub fn setNativeType(
    comptime ret: refl.Type,
    comptime config: anytype,
    native_context: anytype,
    res: anytype,
    js_ctx: v8.Context,
    isolate: v8.Isolate,
) !v8.Value {
    const info = @typeInfo(@TypeOf(res));

    // Optional
    if (info == .Optional) {
        if (res == null) {
            // if null just return JS null
            return isolate.initNull().toValue();
        }
        return setNativeType(
            ret,
            config,
            native_context,
            res.?,
            js_ctx,
            isolate,
        );
    }

    // std.json.Value
    if (ret.T == std.json.Value) return nativeJSONToJS(res, js_ctx, isolate);

    // Union type
    if (comptime ret.union_T) |union_types| {
        // retrieve the active field and setReturntype accordingly
        // NOTE: inspired by std.meta.TagPayloadByName
        const activeTag = @tagName(std.meta.activeTag(res));
        inline for (union_types) |tt| {
            if (std.mem.eql(u8, activeTag, tt.name.?)) {
                return setNativeType(
                    tt,
                    config,
                    native_context,
                    @field(res, tt.name.?),
                    js_ctx,
                    isolate,
                );
            }
        }
    }

    if (ret.nested_index) |nested_index| {

        // return is a user defined nested type

        // create a JS object
        // and call setNativeType on each object fields
        const js_obj = v8.Object.init(isolate);
        const nested = config.app_types[ret.T_refl_index.?].nested[nested_index];
        inline for (nested.fields) |field| {
            const name = field.name.?;
            const js_val = try setNativeType(
                field,
                config,
                native_context,
                @field(res, name),
                js_ctx,
                isolate,
            );
            const key = v8.String.initUtf8(isolate, name);
            if (!js_obj.setValue(js_ctx, key, js_val)) {
                return error.JSObjectSetValue;
            }
        }
        return js_obj.toValue();
    }

    if (ret.T_refl_index) |index| {

        // return is a user defined type

        const js_obj = try setNativeObject(
            config.app_types[index],
            ret.underT(),
            native_context,
            res,
            null,
            isolate,
            js_ctx,
        );

        return js_obj.toValue();
    }

    // return is a builtin type

    const js_val = nativeToJS(
        ret.underT(),
        res,
        isolate,
    ) catch unreachable; // NOTE: should not happen has types have been checked at reflect
    return js_val;
}

// nativeJSONToJS converts a native json value into a JS value.
pub fn nativeJSONToJS(v: std.json.Value, js_ctx: v8.Context, isolate: v8.Isolate) !v8.Value {
    return switch (v) {
        .bool => |vv| nativeToJS(bool, vv, isolate),
        .float => |vv| nativeToJS(f64, vv, isolate),
        .integer => |vv| {
            if (vv >= 0) {
                if (vv <= std.math.maxInt(u32)) {
                    return nativeToJS(u32, @intCast(vv), isolate);
                }
                return nativeToJS(u64, @intCast(vv), isolate);
            }

            if (vv >= std.math.minInt(i32)) {
                return nativeToJS(i32, @intCast(vv), isolate);
            }

            return nativeToJS(i64, vv, isolate);
        },
        .string => |vv| nativeToJS([]const u8, vv, isolate),
        .null => isolate.initNull().toValue(),

        // TODO handle number_string.
        // It is used to represent too big numbers.
        .number_string => return error.TODO,

        .array => |vv| {
            const a = v8.Array.init(isolate, @intCast(vv.items.len));
            const obj = a.castTo(v8.Object);
            for (vv.items, 0..) |vvv, i| {
                const js_val = try nativeJSONToJS(vvv, js_ctx, isolate);
                if (!obj.setValueAtIndex(js_ctx, @intCast(i), js_val)) {
                    return error.JSObjectSetValue;
                }
            }

            return obj.toValue();
        },
        .object => |vv| {
            var obj = v8.Object.init(isolate);
            for (vv.keys()) |k| {
                var js_val: v8.Value = undefined;
                if (vv.get(k)) |vvv| {
                    js_val = try nativeJSONToJS(vvv, js_ctx, isolate);
                } else {
                    // value is null
                    js_val = isolate.initNull().toValue();
                }
                const key = v8.String.initUtf8(isolate, k);
                if (!obj.setValue(js_ctx, key, js_val)) {
                    return error.JSObjectSetValue;
                }
            }
            return obj.toValue();
        },
    };
}

fn postAttach(
    comptime T_refl: refl.Struct,
    comptime argsT: type,
    native_context: anytype,
    obj_ptr: anytype,
    js_obj: v8.Object,
    js_ctx: v8.Context,
) !void {

    // get arguments
    // TODO: merge with getArgs
    var args: argsT = undefined;
    inline for (comptime refl.tupleTypes(argsT), 0..) |field, i| {
        const value = switch (field) {
            @TypeOf(obj_ptr) => obj_ptr,
            JSObject => JSObject{
                .js_ctx = js_ctx,
                .js_obj = js_obj,
                .native_context = native_context,
            },
            else => unreachable,
        };
        const field_name = std.fmt.comptimePrint("{d}", .{i});
        @field(args, field_name) = value;
    }

    // call function
    const f = @field(T_refl.T, "postAttach");
    const ret = comptime try refl.funcReturnType(@TypeOf(f));
    if (comptime refl.isErrorUnion(ret)) {
        _ = try @call(.auto, f, args);
    } else {
        _ = @call(.auto, f, args);
    }
}

fn getNativeObject(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
    native_context: anytype,
    js_obj: v8.Object,
) !*T_refl.Self() {
    const T = T_refl.Self();

    var obj_ptr: *T = undefined;
    if (comptime T_refl.isEmpty()) {
        // if the object is an empty struct (ie. kind of a container)
        // there is no reference from it's constructor, we can just re-create it
        obj_ptr.* = T{};
    } else {
        // retrieve the zig object from it's javascript counterpart

        // check if the js object has a least one internal field.
        if (js_obj.internalFieldCount() == 0) {
            return JSError.InvalidArgument;
        }

        // TODO ensure the js object corresponds to the expected native type.

        const ext = js_obj.getInternalField(0).castTo(v8.External).get().?;
        if (comptime T_refl.is_mem_guarantied()) {
            // memory is fixed
            // ensure the pointer is aligned (no-op at runtime)
            // as External is a ?*anyopaque (ie. *void) with alignment 1
            const ptr: *align(@alignOf(T_refl.Self())) anyopaque = @alignCast(ext);
            if (@hasDecl(T_refl.T, "protoCast")) {
                // T_refl provides a function to cast the pointer from high level Type
                obj_ptr = @call(.auto, @field(T_refl.T, "protoCast"), .{ptr});
            } else {
                // memory layout is fixed through prototype chain of T_refl
                // with the proto Type at the begining of the address of the high level Type
                // so we can safely use @ptrCast
                obj_ptr = @as(*T, @ptrCast(ptr));
            }
        } else {
            // use the refs mechanism to retrieve from high level Type
            obj_ptr = try config.getObject(T, native_context._native_objects, ext);
        }
    }
    return obj_ptr;
}

fn callFunc(
    comptime T_refl: refl.Struct,
    comptime func: refl.Func,
    comptime func_kind: refl.Func.Kind,
    comptime config: anytype,
    cbk_info: CallbackInfo,
    raw_value: ?*const v8.C_Value,
) void {

    // retrieve isolate and context
    const isolate = cbk_info.getIsolate();
    const js_ctx = isolate.getCurrentContext();

    // check func params length
    if (!checkArgsLen(T_refl.name, func, cbk_info, raw_value, isolate)) {
        return;
    }

    // retrieve native context
    const data = cbk_info.getData().castTo(v8.BigInt).getUint64();
    const native_context: *NativeContext(config) = @ptrFromInt(@as(u64, @intCast(data)));

    // prepare args
    var args = getArgs(
        T_refl,
        func,
        config,
        native_context,
        cbk_info,
        raw_value,
        isolate,
        js_ctx,
    ) catch |err| {
        // TODO: how to handle internal errors vs user errors
        const js_err = throwError(
            T_refl,
            func,
            config,
            native_context,
            err,
            isolate,
        );
        cbk_info.getReturnValue().setValueHandle(js_err.handle);
        return;
    };

    // free memory if required
    defer freeArgs(func, config, native_context.allocator, args) catch unreachable;

    // retrieve the zig object
    if (comptime func_kind != .constructor and !T_refl.isEmpty()) {
        const obj_ptr = getNativeObject(T_refl, config, native_context, cbk_info.getThis()) catch unreachable;
        const self_T = @TypeOf(@field(args, "0"));
        if (self_T == T_refl.Self()) {
            @field(args, "0") = obj_ptr.*;
        } else if (self_T == *T_refl.Self() or self_T == *const T_refl.Self()) {
            @field(args, "0") = obj_ptr;
        } else {
            unreachable;
        }
    }

    // call native func
    const function = @field(T_refl.T, func.name);
    const res_T = comptime func.return_type.underErr() orelse func.return_type.T;
    var res: res_T = undefined;
    if (comptime @typeInfo(func.return_type.T) == .ErrorUnion) {
        res = @call(.auto, function, args) catch |err| {
            // TODO: how to handle internal errors vs user errors
            const js_err = throwError(
                T_refl,
                func,
                config,
                native_context,
                err,
                isolate,
            );
            cbk_info.getReturnValue().setValueHandle(js_err.handle);
            return;
        };
    } else {
        res = @call(.auto, function, args);
    }

    if (comptime func_kind == .constructor) {

        // bind native object to JS object this
        _ = setNativeObject(
            T_refl,
            comptime func.return_type.underT(),
            native_context,
            res,
            cbk_info.getThis(),
            isolate,
            js_ctx,
        ) catch unreachable; // TODO: internal errors

    } else if (comptime func_kind == .setter) {
        // on setter, no return value must be the set at all.
    } else {

        // return to javascript the result
        const js_val = setNativeType(
            func.return_type,
            config,
            native_context,
            res,
            js_ctx,
            isolate,
        ) catch |err| blk: {
            break :blk throwError(
                T_refl,
                func,
                config,
                native_context,
                err,
                isolate,
            );
        };
        cbk_info.getReturnValue().setValueHandle(js_val.handle);
    }

    // sync callback
    // for test purpose, does not have any sense in real case
    if (comptime func.callback_index != null) {
        const js_func_index = comptime brk: {
            var idx = func.callback_index.? - func.index_offset;

            // -1 because of self
            if (func.kind != .constructor) idx -= 1;

            break :brk idx;
        };

        if (func.args[js_func_index].T == cbk.FuncSync) {
            args[func.callback_index.? - func.index_offset].call(native_context.allocator) catch unreachable;
        }
    }
}

// JS functions callbacks
// ----------------------

fn generateConstructor(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
) v8.FunctionCallback {
    return struct {
        fn constructor(raw_info: ?*const v8.C_FunctionCallbackInfo) callconv(.C) void {
            const info = v8.FunctionCallbackInfo.initFromV8(raw_info);

            const func = T_refl.constructor orelse {
                const js_err = throwTypeError("Illegal constructor", info.getIsolate());
                info.getReturnValue().set(js_err);
                return;
            };

            // callFunc
            callFunc(
                T_refl,
                func,
                .constructor,
                config,
                .{ .func_cbk = info },
                null,
            );
        }
    }.constructor;
}

fn generateGetter(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
    comptime func: refl.Func,
) v8.AccessorNameGetterCallback {
    return struct {
        fn getter(
            _: ?*const v8.C_Name,
            raw_info: ?*const v8.C_PropertyCallbackInfo,
        ) callconv(.C) void {
            // callFunc
            const info = v8.PropertyCallbackInfo.initFromV8(raw_info);
            callFunc(
                T_refl,
                func,
                .getter,
                config,
                .{ .prop_cbk = info },
                null,
            );
        }
    }.getter;
}

fn generateSetter(
    comptime T_refl: refl.Struct,
    comptime config: anytype,
    comptime func: refl.Func,
) v8.AccessorNameSetterCallback {
    return struct {
        fn setter(
            _: ?*const v8.C_Name,
            raw_value: ?*const v8.C_Value,
            raw_info: ?*const v8.C_PropertyCallbackInfo,
        ) callconv(.C) void {

            // callFunc
            const info = v8.PropertyCallbackInfo.initFromV8(raw_info);
            callFunc(
                T_refl,
                func,
                .setter,
                config,
                .{ .prop_cbk = info },
                raw_value,
            );
        }
    }.setter;
}

fn generateMethod(
    comptime T_refl: refl.Struct,
    comptime func: refl.Func,
    comptime config: anytype,
) v8.FunctionCallback {
    return struct {
        fn method(raw_info: ?*const v8.C_FunctionCallbackInfo) callconv(.C) void {

            // callFunc
            const info = v8.FunctionCallbackInfo.initFromV8(raw_info);
            callFunc(
                T_refl,
                func,
                .method,
                config,
                .{ .func_cbk = info },
                null,
            );
        }
    }.method;
}

fn generateStringTag(comptime name: []const u8) v8.AccessorNameGetterCallback {
    return struct {
        fn stringTag(
            _: ?*const v8.C_Name,
            raw_info: ?*const v8.C_PropertyCallbackInfo,
        ) callconv(.C) void {
            const info = v8.PropertyCallbackInfo.initFromV8(raw_info);
            const js_name = v8.String.initUtf8(info.getIsolate(), name);
            info.getReturnValue().set(js_name);
        }
    }.stringTag;
}

fn staticAttrsKeys(
    comptime T_refl: refl.Struct,
    keys: []v8.Name,
    isolate: v8.Isolate,
) void {
    const attrs_T = T_refl.static_attrs_T orelse return;
    inline for (@typeInfo(attrs_T).Struct.fields, 0..) |field, i| {
        keys[i] = v8.String.initUtf8(isolate, field.name).toName();
    }
}

fn staticAttrsValues(
    comptime T_refl: refl.Struct,
    values: []v8.Value,
    isolate: v8.Isolate,
) void {
    const attrs_T = T_refl.static_attrs_T orelse return;
    const attrs = comptime T_refl.staticAttrs(attrs_T);
    inline for (@typeInfo(attrs_T).Struct.fields, 0..) |field, i| {
        const value = comptime @field(attrs, field.name);
        values[i] = nativeToJS(@TypeOf(value), value, isolate) catch unreachable;
    }
}

fn setStaticAttrs(
    comptime T_refl: refl.Struct,
    template: anytype,
    keys: []v8.Name,
    values: []v8.Value,
) void {
    if (T_refl.static_attrs_T == null) {
        return;
    }
    const attrs_T = T_refl.static_attrs_T.?;
    inline for (@typeInfo(attrs_T).Struct.fields, 0..) |_, i| {
        template.set(keys[i], values[i], v8.PropertyAttribute.ReadOnly + v8.PropertyAttribute.DontDelete);
    }
}
