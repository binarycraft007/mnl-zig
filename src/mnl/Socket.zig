pub const BusId = enum(u5) {
    route = 0, // Routing/device hook
    unused, // Unused number
    usersock, // Reserved for user mode socket protocols
    firewall, // Unused number, formerly ip_queue
    sock_diag, // socket monitoring
    nflog, // netfilter/iptables ULOG
    xfrm, // ipsec
    selinux, // SELinux event notifications
    iscsi, // Open-iSCSI
    audit, // auditing
    fib_lookup,
    connector,
    netfilter, // netfilter subsystem
    ip6_fw,
    dnrtmsg, // DECnet routing messages (obsolete)
    kobject_uevent, // Kernel messages to userspace
    generic,
    // leave room for NETLINK_DM (DM Events)
    scsitransport = 18, // SCSI Transports
    ecryptfs,
    rdma,
    crypto, // Crypto layer
    smc, // SMC monitoring
};

pub const OptionName = enum(u3) {
    add_membership = 1,
    drop_membership,
    pktinfo,
    broadcast_error,
    no_enobufs,
};

pub const Address = extern union {
    any: os.sockaddr,
    nl: NlAddress,

    pub fn getOsSockLen(self: Address) os.socklen_t {
        switch (self.any.family) {
            os.AF.NETLINK => {
                return @as(os.socklen_t, @intCast(@sizeOf(os.sockaddr.nl)));
            },

            else => unreachable,
        }
    }

    pub fn initNl(pid: u32, groups: u32) Address {
        return Address{ .nl = NlAddress.init(pid, groups) };
    }
};

pub const NlAddress = extern struct {
    sa: os.sockaddr.nl,

    pub fn init(pid: u32, groups: u32) NlAddress {
        return .{ .sa = .{ .pid = pid, .groups = groups } };
    }
};

sockfd: os.socket_t,
addr: Address = undefined,

/// open a netlink socket
pub fn open(bus: BusId) os.SocketError!Socket {
    return try openImpl(@intFromEnum(bus), 0);
}

/// open a netlink socket with appropriate flags
/// `bus` the netlink socket bus ID (see BusId enum)
/// `flags` the netlink socket flags (see os.SOCK.* constants)
/// This is similar to open(), but allows one to set flags like
/// SOCK.CLOEXEC at socket creation time (useful for multi-threaded programs
/// performing exec calls).
pub fn open2(bus: BusId, flags: u32) os.SocketError!Socket {
    return try openImpl(@intFromEnum(bus), flags);
}

pub const SetSockOptError = os.SetSockOptError;

/// set Netlink socket option
pub fn setsockopt(self: *Socket, optname: OptionName, opt: []const u8) SetSockOptError!void {
    return try os.setsockopt(self.sockfd, os.SOL.NETLINK, @intFromEnum(optname), opt);
}

pub const GetSockOptError = os.SetSockOptError;

/// get a Netlink socket option
pub fn getsockopt(self: *Socket, optname: OptionName, opt: []const u8) GetSockOptError!void {
    switch (os.errno(os.system.setsockopt(
        self.sockfd,
        os.SOL.NETLINK,
        @intFromEnum(optname),
        opt.ptr,
        @as(os.socklen_t, @intCast(opt.len)),
    ))) {
        .SUCCESS => {},
        .BADF => unreachable, // always a race condition
        .NOTSOCK => unreachable, // always a race condition
        .INVAL => unreachable,
        .FAULT => unreachable,
        .DOM => return error.TimeoutTooBig,
        .ISCONN => return error.AlreadyConnected,
        .NOPROTOOPT => return error.InvalidProtocolOption,
        .NOMEM => return error.SystemResources,
        .NOBUFS => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        .NODEV => return error.NoDevice,
        else => |err| return os.unexpectedErrno(err),
    }
}

pub const BindError = os.BindError || os.GetSockNameError;
pub fn bind(self: *Socket, groups: u32, pid: os.pid_t) BindError!void {
    self.addr = Address.initNl(pid, groups);
    try os.bind(self.sockfd, &self.addr, self.addr.getOsSockLen());
    try os.getsockname(self.sockfd, self.addr, self.addr.getOsSockLen());
    std.debug.assert(self.addr.any.family == os.AF.NETLINK);
}

pub const FdOpenError = os.GetSockNameError;
pub fn fdopen(sockfd: os.socket_t) FdOpenError!Socket {
    var addr: Address = undefined;
    try os.getsockname(sockfd, addr, addr.getOsSockLen());
    std.debug.assert(addr.any.family == os.AF.NETLINK);
    return .{ .sockfd = sockfd, .addr = addr };
}

pub const SendToError = os.SendToError;
pub fn sendto(self: *Socket, buf: []const u8) SendToError!void {
    try os.sendto(self.sockfd, buf, 0, self.addr, self.addr.getOsSockLen());
}

pub const RecvFromError = os.RecvFromError;
pub fn recvfrom(self: *Socket, buf: []const u8) RecvFromError!void {
    var iov: os.iovec = .{ .iov_base = buf.ptr, .iov_len = buf.len };
    var msg: os.msghdr = .{
        .name = &self.addr,
        .namelen = self.addr.getOsSockLen(),
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    while (true) {
        const rc = os.system.recvmsg(self.sockfd, &msg, 0);
        switch (os.errno(rc)) {
            .SUCCESS => return @as(usize, @intCast(rc)),
            .BADF => unreachable, // always a race condition
            .FAULT => unreachable,
            .INVAL => unreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => unreachable,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .NOMEM => return error.SystemResources,
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            else => |err| return os.unexpectedErrno(err),
        }
    }
}

/// close a given netlink socket
pub fn close(self: *Socket) void {
    os.closeSocket(self.sockfd);
}

inline fn openImpl(bus: u32, flags: u32) os.SocketError!Socket {
    return .{ .sockfd = try os.socket(os.AF.NETLINK, os.SOCK.RAW | flags, bus) };
}

const std = @import("std");
const os = std.os;
const Socket = @This();
