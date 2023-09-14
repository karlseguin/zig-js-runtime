const std = @import("std");

const internal = @import("internal_api.zig");
const refl = internal.refl;

// Map references all objects created in both JS and Native world
// either from JS through a constructor template call
// or from Native in an addObject call
// - key is the adress of the object (as an int)
// it will be store on the JS object as an internal field
// - value is the index of API
pub const Map = std.AutoHashMapUnmanaged(usize, usize);
pub var map: Map = undefined;

pub fn addObject(alloc: std.mem.Allocator, key: usize, value: usize) !void {
    try map.put(alloc, key, value);
}

pub fn getObject(comptime T: type, comptime types: []refl.Struct, ptr: anytype) !*T {

    // use the object pointer (key) to retrieve the API index (value) in the map
    const ptr_aligned: *align(8) anyopaque = @alignCast(ptr);
    const key: *usize = @ptrCast(ptr_aligned);
    const T_index = map.get(key.*);
    if (T_index == null) {
        return error.NullReference;
    }

    // get the API corresponding to the API index
    // TODO: more efficient sorting?
    inline for (types) |T_refl| {
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
