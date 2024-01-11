pub const Header = os.linux.nlmsghdr;
pub const header_size = @sizeOf(Header);

buf: []align(align_to) u8,

pub fn header(self: *const Message) *Header {
    return @ptrCast(@alignCast(self.buf[0..header_size]));
}

pub fn size(self: *const Message) usize {
    return self.header().len;
}

pub fn payloadLen(self: *const Message) usize {
    return self.header().len - alignedSize(header_size);
}

pub fn putHeader(self: *Message) void {
    const aligned_len = alignedSize(header_size);
    @memset(self.buf[0..aligned_len], 0);
    self.header().len = @intCast(aligned_len);
}

pub fn putExtraHeader(self: *Message, len: usize) []align(align_to) u8 {
    var buf = self.buf[header_size..];
    const aligned_len = alignedSize(len);
    self.header().len += @intCast(aligned_len);
    @memset(buf[0..aligned_len], 0);
    return buf;
}

pub fn getPayload(self: *const Message) []align(align_to) u8 {
    return @alignCast(self.buf[alignedSize(header_size)..]);
}

pub fn getPayloadOffset(self: *const Message, offset: usize) []u8 {
    return self.buf[alignedSize(header_size) + offset ..];
}

pub fn isMessageOk(self: *const Message) bool {
    if (self.buf.len < header_size) return false;
    if (self.header().len < header_size) return false;
    if (self.header().len > self.buf.len) return false;
    return true;
}

pub fn next(self: *const Message) ?Message {
    if (!self.isMessageOk()) return null;
    return .{ .buf = @alignCast(self.buf[alignedSize(self.header().len)..]) };
}

pub fn getPayloadTail(self: *const Message) []align(align_to) u8 {
    return @alignCast(self.buf[alignedSize(self.header().len)..]);
}

pub fn isSeqOk(self: *const Message, seq: u32) bool {
    return self.fieldCheck(.seq, seq);
}

pub fn isPortIdOk(self: *const Message, pid: u32) bool {
    return self.fieldCheck(.pid, pid);
}

pub const Field = enum { seq, pid };

inline fn fieldCheck(self: *const Message, comptime field: Field, value: u32) bool {
    if (@field(self.header(), @tagName(field)) > 0) {
        if (value > 0) return @field(self.header(), @tagName(field)) == value;
        return true;
    }
    return false;
}

pub const Batch = struct {
    buf: []align(align_to) u8,
    len: usize = 0,
    cur: usize = 0,
    limit: usize = Socket.buffer_size,
    overflow: bool = false,

    pub fn start(buf: []align(align_to) u8) Batch {
        std.debug.assert(buf.len == 2 * Socket.buffer_size);
        return .{ .buf = buf };
    }

    pub fn stop(self: *Batch) void {
        self.buf = undefined;
    }

    pub fn next(self: *Batch) bool {
        const h: *Header = @ptrCast(@alignCast(self.buf[self.cur..header_size]));
        if (self.len + h.len > self.limit) {
            self.overflow = true;
            return false;
        }
        self.cur = self.len + h.len;
        self.len += h.len;
        return true;
    }

    pub fn reset(self: *Batch) void {
        if (self.overflow) {
            const h: *Header = @ptrCast(@alignCast(self.buf[self.cur..header_size]));
            @memcpy(self.buf[0..h.len], self.buf[self.cur..h.len]);
            self.len = h.len;
            self.cur = self.len;
            self.overflow = false;
        } else {
            self.len = 0;
            self.cur = 0;
        }
    }

    pub fn head(self: *Batch) []align(align_to) u8 {
        return @alignCast(self.buf[0..]);
    }

    pub fn current(self: *Batch) []align(align_to) u8 {
        return @alignCast(self.buf[self.cur..]);
    }

    pub fn empty(self: *Batch) bool {
        return self.len == 0;
    }

    pub fn size(self: *Batch) usize {
        return self.len;
    }
};

const std = @import("std");
const os = std.os;
const mem = std.mem;
const root = @import("../root.zig");
const align_to = root.align_to;
const alignedSize = root.alignedSize;
const Message = @This();
const Socket = @import("Socket.zig");
