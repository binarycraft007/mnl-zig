/// libmnl is a minimalistic user-space library oriented to Netlink developers.
/// There are a lot of common tasks in parsing, validating, constructing of
/// both the Netlink header and TLVs that are repetitive and easy to get wrong.
/// This library aims to provide simple helpers that allows you to avoid
/// re-inventing the wheel in common Netlink tasks.
pub const align_to = 4; //  fixed to 4 bytes
pub const Socket = @import("mnl/Socket.zig"); // Netlink socket API
pub const Message = @import("mnl/Message.zig"); // Netlink message API
pub const Attribute = @import("mnl/Attribute.zig"); // Netlink attribute API

pub inline fn alignedSize(len: usize) usize {
    return @import("std").mem.alignForward(usize, len, align_to);
}

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
