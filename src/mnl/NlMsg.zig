pub const align_to = 4; //  fixed to 4 bytes
pub const header_size = @sizeOf(os.linux.nlmsghdr);

buf: []align(align_to) u8,

inline fn alignedSize(len: usize) usize {
    return mem.alignForward(usize, len, align_to);
}

pub fn header(self: *const NlMsg) *os.linux.nlmsghdr {
    return @ptrCast(@alignCast(self.buf[0..header_size]));
}

pub fn size(self: *const NlMsg) usize {
    return self.header().len;
}

pub fn payloadLen(self: *const NlMsg) usize {
    return self.header().len - header_size;
}

pub fn putHeader(self: *NlMsg) void {
    const aligned_len = alignedSize(header_size);
    @memset(self.buf[0..aligned_len], 0);
    self.header().len = aligned_len;
}

pub fn putExtraHeader(self: *NlMsg, len: usize) []u8 {
    var buf = self.buf[header_size..];
    const aligned_len = alignedSize(len);
    self.header().len += aligned_len;
    @memset(buf[0..aligned_len], 0);
    return buf;
}

pub fn getPayload(self: *NlMsg) []u8 {
    return self.buf[header_size..];
}

pub fn getPayloadOffset(self: *NlMsg, offset: usize) []u8 {
    return self.buf[header_size + offset ..];
}

pub fn isMsgOk(self: *const NlMsg, len: isize) bool {
    const ulen: usize = @intCast(len);
    if (len < 0) return false;
    return ulen >= header_size and
        self.header().len >= header_size and
        self.header().len <= ulen;
}

//pub fn next(self: *const NlMsg) ?NlMsg {
//
//}

const std = @import("std");
const os = std.os;
const mem = std.mem;
const NlMsg = @This();
