//! Exporting tls key so we can share them with Wireshark and analyze decrypted
//! traffic in Wireshark.
//! To configure Wireshark to use exported keys see curl reference.
//!
//! References:
//! curl: https://everything.curl.dev/usingcurl/tls/sslkeylogfile.html
//! openssl: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_keylog_callback.html
//! https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format

const std = @import("std");

const key_log_file_env = "SSLKEYLOGFILE";

pub const label = struct {
    // tls 1.3
    pub const client_handshake_traffic_secret: []const u8 = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    pub const server_handshake_traffic_secret: []const u8 = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    pub const client_traffic_secret_0: []const u8 = "CLIENT_TRAFFIC_SECRET_0";
    pub const server_traffic_secret_0: []const u8 = "SERVER_TRAFFIC_SECRET_0";
    // tls 1.2
    pub const client_random: []const u8 = "CLIENT_RANDOM";
};

var environ: std.process.Environ = .empty;

pub const Callback = *const fn (label: []const u8, client_random: []const u8, secret: []const u8) void;

pub fn init(env: std.process.Environ) Callback {
    environ = env;
    return callback;
}

/// Writes tls keys to the file pointed by SSLKEYLOGFILE environment variable.
pub fn callback(label_: []const u8, client_random: []const u8, secret: []const u8) void {
    const allocator = std.heap.page_allocator;
    const file_name = environ.getAlloc(allocator, key_log_file_env) catch |err| switch (err) {
        error.EnvironmentVariableMissing => return,
        else => {
            std.debug.print("key_log: SSLKEYLOGFILE lookup error: {s}\n", .{@errorName(err)});
            return;
        },
    };
    defer allocator.free(file_name);

    fileAppend(file_name, label_, client_random, secret) catch |err| {
        std.debug.print("key_log: write error: {s}\n", .{@errorName(err)});
    };
}

fn fileAppend(file_name: []const u8, label_: []const u8, client_random: []const u8, secret: []const u8) !void {
    var buf: [1024]u8 = undefined;
    const line = try formatLine(&buf, label_, client_random, secret);
    try fileWrite(file_name, line);
}

fn fileWrite(file_name: []const u8, line: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    var file = std.Io.Dir.openFileAbsolute(io, file_name, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => try std.Io.Dir.createFileAbsolute(io, file_name, .{ .read = true, .truncate = false }),
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    try file.writePositionalAll(io, line, stat.size);
}

fn formatLine(buf: []u8, label_: []const u8, client_random: []const u8, secret: []const u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try w.print("{s} ", .{label_});
    for (client_random) |b| {
        try w.print("{x:0>2}", .{b});
    }
    try w.writeByte(' ');
    for (secret) |b| {
        try w.print("{x:0>2}", .{b});
    }
    try w.writeByte('\n');
    return w.buffered();
}
