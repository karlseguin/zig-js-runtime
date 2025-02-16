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

const JS = public.Config(.{ Brand, Car, Country, JSONGen }, void);

const tests = public.test_utils;

// Native types with separate APIs
// -------------------------------

const Brand = struct {
    name: []const u8,
    allocator: Allocator,

    pub fn constructor(allocator: Allocator, name: []const u8) Brand {
        return .{
            .allocator = allocator,
            .name = allocator.dupe(u8, name) catch unreachable,
        };
    }

    pub fn get_name(self: Brand) []const u8 {
        return self.name;
    }

    pub fn set_name(self: *Brand, name: []u8) void {
        self.name = self.allocator.dupe(u8, name) catch unreachable;
    }

    pub fn deinit(self: *Brand) void {
        self.allocator.free(self.name);
    }
};

const Car = struct {
    brand: Brand,
    brand_ptr: *Brand,

    pub fn constructor(allocator: Allocator) Car {
        const brand_name: []const u8 = "Renault";
        const brand = Brand{ .allocator = allocator, .name = brand_name };
        const brand_ptr = allocator.create(Brand) catch unreachable;
        brand_ptr.* = Brand{ .allocator = allocator, .name = brand_name };
        return .{ .brand = brand, .brand_ptr = brand_ptr };
    }

    // As argument
    // -----------

    // accept <Struct> in setter
    pub fn set_brand(self: *Car, brand: Brand) void {
        self.brand = brand;
    }

    // accept *<Struct> in setter
    pub fn set_brandPtr(self: *Car, brand_ptr: *Brand) void {
        self.brand_ptr = brand_ptr;
    }

    // accept <Struct> in method
    pub fn _changeBrand(self: *Car, brand: Brand) void {
        self.brand = brand;
    }

    // accept *<Struct> in method
    pub fn _changeBrandPtr(self: *Car, brand_ptr: *Brand) void {
        self.brand_ptr = brand_ptr;
    }

    // accept ?<Struct> in method
    pub fn _changeBrandOpt(self: *Car, brand: ?Brand) void {
        if (brand != null) {
            self.brand = brand.?;
        }
    }

    // accept ?*<Struct> in method
    pub fn _changeBrandOptPtr(self: *Car, brand_ptr: ?*Brand) void {
        if (brand_ptr != null) {
            self.brand_ptr = brand_ptr.?;
        }
    }

    // As return value
    // ---------------

    // return <Struct> in getter
    pub fn get_brand(self: Car) Brand {
        return self.brand;
    }

    // return *<Struct> in getter
    pub fn get_brandPtr(self: Car) *Brand {
        return self.brand_ptr;
    }

    // return ?<Struct> in getter
    pub fn get_brandOpt(self: Car) ?Brand {
        return self.brand;
    }

    // return ?*<Struct> in getter
    pub fn get_brandPtrOpt(self: Car) ?*Brand {
        return self.brand_ptr;
    }

    // return ?<Struct> null in getter
    pub fn get_brandOptNull(_: Car) ?Brand {
        return null;
    }

    // return ?*<Struct> null in getter
    pub fn get_brandPtrOptNull(_: Car) ?*Brand {
        return null;
    }

    // return <Struct> in method
    pub fn _getBrand(self: Car) Brand {
        return self.get_brand();
    }

    // return *<Struct> in method
    pub fn _getBrandPtr(self: Car) *Brand {
        return self.get_brandPtr();
    }

    pub fn deinit(self: *Car, allocator: Allocator) void {
        allocator.destroy(self.brand_ptr);
    }
};

// Native types with nested APIs
// -----------------------------

const Country = struct {
    stats: Stats,

    // Nested type
    // -----------
    // NOTE: Nested types are objects litterals only supported as function argument,
    // typically for Javascript options.
    pub const Stats = struct {
        population: ?u32,
        pib: []const u8,
    };

    // As argument
    // -----------

    // <NestedStruct> in method arg
    pub fn constructor(stats: Stats) Country {
        return .{ .stats = stats };
    }

    pub fn get_population(self: Country) ?u32 {
        return self.stats.population;
    }

    pub fn get_pib(self: Country) []const u8 {
        return self.stats.pib;
    }

    // ?<NestedStruct> optional in method arg
    pub fn _changeStats(self: *Country, stats: ?Stats) void {
        if (stats) |s| {
            self.stats = s;
        }
    }

    // *<Struct> (ie. pointer) is not supported by design,
    // for a pointer use case, use a seperate Native API.

    // As return value
    // ---------------

    // return <NestedStruct> in getter
    pub fn get_stats(self: Country) Stats {
        return self.stats;
    }

    // return ?<NestedStruct> in method (null)
    pub fn _doStatsNull(_: Country) ?Stats {
        return null;
    }

    // return ?<NestedStruct> in method (non-null)
    pub fn _doStatsNotNull(self: Country) ?Stats {
        return self.stats;
    }
};

const JSONGen = struct {
    jsobj: std.json.Parsed(std.json.Value),

    pub fn constructor(allocator: Allocator) !JSONGen {
        return .{
            .jsobj = try std.json.parseFromSlice(std.json.Value, allocator,
                \\{
                \\   "str": "bar",
                \\   "int": 123,
                \\   "float": 123.456,
                \\   "array": [1,2,3],
                \\   "neg": -123,
                \\   "max": 1.7976931348623157e+308,
                \\   "min": 5e-324,
                \\   "max_safe_int": 9007199254740991,
                \\   "max_safe_int_over": 9007199254740992
                \\}
            , .{}),
        };
    }

    pub fn _object(self: JSONGen) std.json.Value {
        return self.jsobj.value;
    }

    pub fn deinit(self: *JSONGen) void {
        self.jsobj.deinit();
    }
};

test "integration: native types" {
    var buf: [1024 * 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var runner = try tests.CaseRunner(JS).init(fba.allocator(), {});
    defer runner.deinit();

    var nested_arg = [_]tests.Case{
        .{ .src = "let stats = {'pib': '322Mds', 'population': 80}; let country = new Country(stats);", .ex = "undefined" },
        .{ .src = "country.population;", .ex = "80" },
        .{ .src = "let stats_without_population = {'pib': '342Mds'}; country.changeStats(stats_without_population)", .ex = "undefined" },
        .{ .src = "let stats2 = {'pib': '342Mds', 'population': 80}; country.changeStats(stats2);", .ex = "undefined" },
        .{ .src = "country.pib;", .ex = "342Mds" },
        .{ .src = "country.stats.pib;", .ex = "342Mds" },
        .{ .src = "country.doStatsNull();", .ex = "null" },
        .{ .src = "country.doStatsNotNull().pib;", .ex = "342Mds" },
    };
    try runner.run(&nested_arg);

    var separate_cases = [_]tests.Case{
        .{ .src = "let car = new Car();", .ex = "undefined" },

        // basic tests for getter
        .{ .src = "let brand1 = car.brand", .ex = "undefined" },
        .{ .src = "brand1.name", .ex = "Renault" },
        .{ .src = "let brand1Ptr = car.brandPtr", .ex = "undefined" },
        .{ .src = "brand1Ptr.name", .ex = "Renault" },

        // basic test for method
        .{ .src = "let brand2 = car.getBrand()", .ex = "undefined" },
        .{ .src = "brand2.name", .ex = "Renault" },
        .{ .src = "brand2 !== brand1", .ex = "true" }, // return value, not equal
        .{ .src = "let brand2Ptr = car.getBrandPtr()", .ex = "undefined" },
        .{ .src = "brand2Ptr.name", .ex = "Renault" },
        .{ .src = "brand2Ptr === brand1Ptr", .ex = "true" }, // return pointer, strict equal

        // additional call for pointer, to ensure persistent
        .{ .src = "let brand2BisPtr = car.getBrandPtr()", .ex = "undefined" },
        .{ .src = "brand2BisPtr.name", .ex = "Renault" },
        .{ .src = "brand2BisPtr === brand1Ptr", .ex = "true" }, // return pointer, strict equal
        .{ .src = "brand2BisPtr === brand2Ptr", .ex = "true" }, // return pointer, strict equal

        // successive calls for getter value
        // check the set of a new name on brand1 (value) has no impact
        .{ .src = "brand1.name = 'Peugot'", .ex = "Peugot" },
        .{ .src = "let brand1_again = car.brand", .ex = "undefined" },
        .{ .src = "brand1_again.name", .ex = "Renault" },
        // check the set of a new name on brand1Ptr (pointer) has impact
        // ie. successive calls return the same pointer
        .{ .src = "brand1Ptr.name = 'Peugot'", .ex = "Peugot" },
        .{ .src = "let brand1Ptr_again = car.brandPtr", .ex = "undefined" },
        .{ .src = "brand1Ptr_again.name", .ex = "Peugot" },
        // and check back the set of a new name on brand1Ptr_agin in brand1Ptr
        .{ .src = "brand1Ptr_again.name = 'Citroën'", .ex = "Citroën" },
        .{ .src = "brand1Ptr.name", .ex = "Citroën" },

        // null test
        .{ .src = "let brand_opt = car.brandOpt", .ex = "undefined" },
        .{ .src = "brand_opt.name", .ex = "Renault" },
        .{ .src = "let brand_ptr_opt = car.brandPtrOpt", .ex = "undefined" },
        .{ .src = "brand_ptr_opt.name", .ex = "Citroën" },
        .{ .src = "car.brandOptNull", .ex = "null" },
        .{ .src = "car.brandPtrOptNull", .ex = "null" },

        // as argumemnt for setter
        .{ .src = "let brand3 = new Brand('Audi')", .ex = "undefined" },
        .{ .src = "var _ = (car.brand = brand3)", .ex = "undefined" },
        .{ .src = "car.brand.name === 'Audi'", .ex = "true" },
        .{ .src = "var _ = (car.brandPtr = brand3)", .ex = "undefined" },
        .{ .src = "car.brandPtr.name === 'Audi'", .ex = "true" },

        // as argumemnt for methods
        .{ .src = "let brand4 = new Brand('Tesla')", .ex = "undefined" },
        .{ .src = "car.changeBrand(brand4)", .ex = "undefined" },
        .{ .src = "car.brand.name === 'Tesla'", .ex = "true" },
        .{ .src = "car.changeBrandPtr(brand4)", .ex = "undefined" },
        .{ .src = "car.brandPtr.name === 'Tesla'", .ex = "true" },

        .{ .src = "let brand5 = new Brand('Audi')", .ex = "undefined" },
        .{ .src = "car.changeBrandOpt(brand5)", .ex = "undefined" },
        .{ .src = "car.brand.name === 'Audi'", .ex = "true" },
        .{ .src = "car.changeBrandOpt(null)", .ex = "undefined" },
        .{ .src = "car.brand.name === 'Audi'", .ex = "true" },

        .{ .src = "let brand6 = new Brand('Ford')", .ex = "undefined" },
        .{ .src = "car.changeBrandOptPtr(brand6)", .ex = "undefined" },
        .{ .src = "car.brandPtr.name === 'Ford'", .ex = "true" },
        .{ .src = "car.changeBrandOptPtr(null)", .ex = "undefined" },
        .{ .src = "car.brandPtr.name === 'Ford'", .ex = "true" },
    };
    try runner.run(&separate_cases);

    var bug_native_obj = [_]tests.Case{
        // Test for the bug #185: native func expects a object but the js value is
        // not.
        // https://github.com/lightpanda-io/jsruntime-lib/issues/185
        .{ .src = "try { car.changeBrand('foo'); false; } catch(e) { e instanceof TypeError; }", .ex = "true" },
        // Test for the bug #187: native func expects a native object but the js value is
        // not.
        // https://github.com/lightpanda-io/jsruntime-lib/issues/187
        .{ .src = "try { car.changeBrand({'foo': 'bar'}); false; } catch(e) { e instanceof TypeError; }", .ex = "true" },
    };
    try runner.run(&bug_native_obj);

    var json_native = [_]tests.Case{
        .{ .src = "let json = (new JSONGen()).object()", .ex = "undefined" },
        .{ .src = "json.str", .ex = "bar" },
        .{ .src = "json.int", .ex = "123" },
        .{ .src = "json.float", .ex = "123.456" },
        .{ .src = "json.neg", .ex = "-123" },
        .{ .src = "json.min", .ex = "5e-324" },
        .{ .src = "json.max", .ex = "1.7976931348623157e+308" },

        .{ .src = "json.max_safe_int", .ex = "9007199254740991" },
        .{ .src = "json.max_safe_int_over", .ex = "9007199254740992" },

        .{ .src = "typeof(json.int)", .ex = "number" },
        .{ .src = "typeof(json.float)", .ex = "number" },
        .{ .src = "typeof(json.neg)", .ex = "number" },
        .{ .src = "typeof(json.max)", .ex = "number" },
        .{ .src = "typeof(json.min)", .ex = "number" },

        // TODO these tests should pass, but we've got bigint instead.
        //.{ .src = "typeof(json.max_safe_int)", .ex = "number" },
        //.{ .src = "typeof(json.max_safe_int_over)", .ex = "number" },

        .{ .src = "json.array.length", .ex = "3" },
        .{ .src = "json.array[0]", .ex = "1" },
    };
    try runner.run(&json_native);
}
