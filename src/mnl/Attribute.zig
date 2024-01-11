/// <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
/// +---------------------+- - -+- - - - - - - - - -+- - -+
/// |        Header       | Pad |     Payload       | Pad |
/// |   (struct nlattr)   | ing |                   | ing |
/// +---------------------+- - -+- - - - - - - - - -+- - -+
/// <-------------- nlattr->nla_len -------------->
pub const Header = extern struct {
    len: u16 = 0,
    type: u16 = 0,

    pub const size = @sizeOf(@This());
};

pub const Type = enum(u4) {
    INVALID = 0,
    FLAG,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    BINARY,
    STRING,
    NUL_STRING,
    NESTED,
    NESTED_ARRAY,
    BITFIELD32,
};

/// nla_type (16 bits)
/// +---+---+-------------------------------+
/// | N | O | Attribute Type                |
/// +---+---+-------------------------------+
/// N := Carries nested attributes
/// O := Payload stored in network byte order
///
/// Note: The N and O flag are mutually exclusive.
pub const F_NESTED: u16 = 1 << 15;
pub const F_NET_BYTEORDER: u16 = 1 << 14;
pub const TYPE_MASK: u16 = ~(F_NESTED | F_NET_BYTEORDER);

buf: []align(align_to) u8,

pub fn header(self: *const Attribute) *Header {
    return @ptrCast(self.buf[0..Header.size]);
}

pub fn getType(self: *const Attribute) Type {
    return @enumFromInt(self.header().type & TYPE_MASK);
}

pub fn getLen(self: *const Attribute) usize {
    return self.header().len;
}

pub fn payloadLen(self: *const Attribute) usize {
    return self.header().len - alignedSize(Header.size);
}

pub fn payload(self: *Attribute) []align(align_to) u8 {
    return @alignCast(self.buf[0..self.header().len]);
}

const std = @import("std");
const os = std.os;
const root = @import("../root.zig");
const align_to = root.align_to;
const alignedSize = root.alignedSize;
const Attribute = @This();
const Message = @import("Message.zig");
