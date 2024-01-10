/// libmnl is a minimalistic user-space library oriented to Netlink developers.
/// There are a lot of common tasks in parsing, validating, constructing of
/// both the Netlink header and TLVs that are repetitive and easy to get wrong.
/// This library aims to provide simple helpers that allows you to avoid
/// re-inventing the wheel in common Netlink tasks.
pub const Socket = @import("mnl/Socket.zig"); // Netlink socket API

test "open/close socket" {
    var sock = try Socket.open(.generic);
    defer sock.close();
}

const std = @import("std");
const testing = std.testing;
