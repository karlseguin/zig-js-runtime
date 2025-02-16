const std = @import("std");

const public = @import("../api.zig");
const tests = public.test_utils;

const js_config = public.Config(.{
    Request,
}, Config);

const Config = struct {
    use_proxy: bool,
};

const Request = struct {
    use_proxy: bool,

    pub fn constructor(ctx: Config) Request {
        return .{
            .use_proxy = ctx.use_proxy,
        };
    }

    pub fn get_proxy(self: *Request) bool {
        return self.use_proxy;
    }

    pub fn _configProxy(_: *Request, ctx: Config) bool {
        return ctx.use_proxy;
    }
};

test "integration: app_context" {
    var buf: [1024 * 4]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var runner = try tests.CaseRunner(js_config).init(fba.allocator(), .{
        .use_proxy = true,
    });
    defer runner.deinit();

    var tc = [_]tests.Case{
        .{ .src = "const req = new Request();", .ex = "undefined" },
        .{ .src = "req.proxy", .ex = "true" },
        .{ .src = "req.configProxy()", .ex = "true" },
    };
    try runner.run(&tc);
}
