//! TLS alerts (RFC 8446 §6): two bytes, of which the description does
//! nearly all the work. TLS 1.3 deprecates the level byte and §6 makes
//! every alert but close_notify and user_canceled fatal whatever level
//! it claims — so for those, the level tells a reader nothing.
//!
//! `user_canceled` is the exception, and it is not a small one:
//! `disposition` tolerates it at warning level and treats it as fatal at
//! fatal level, because §6.1 leaves it legal as a *signal* and a peer
//! sending it fatally is aborting. Reading the level as decoration there
//! would discard a peer's abort. This comment used to say the byte
//! carried no information at all, which was true until that arrived.

const std = @import("std");
const assert = std.debug.assert;

pub const bytes = 2;

pub const Level = enum(u8) {
    warning = 1,
    fatal = 2,
};

/// The descriptions zssl emits or names in decisions. Peers may send any
/// byte; `Alert.description` answers null for ones outside this set and
/// the connection treats them as fatal, which §6 requires anyway.
pub const Description = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    /// The peer's certificate could not be read, or its key is outside
    /// `ClientHandshake`'s policy — §4.4.2's refusal, not §4.4.3's.
    bad_certificate = 42,
    illegal_parameter = 47,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    missing_extension = 109,
    unsupported_extension = 110,
    user_canceled = 90,
    no_application_protocol = 120,
};

pub const Alert = struct {
    level_wire: u8,
    description_wire: u8,

    pub fn description(self: *const Alert) ?Description {
        assert(self.level_wire >= 1);
        return std.enums.fromInt(Description, self.description_wire);
    }

    pub fn isCloseNotify(self: *const Alert) bool {
        assert(self.level_wire >= 1);
        return self.description_wire == @intFromEnum(Description.close_notify);
    }
};

/// What §6.1 says to do with an alert that arrived, decided in one place
/// because both handshakes decide it identically.
pub const Disposition = enum {
    /// close_notify: the peer is done sending. §6.1.
    close,
    /// A warning-level `user_canceled`. TLS 1.3 meant to remove warning
    /// alerts and left this one defined without saying how to handle it,
    /// and JDK 11 sends it after the handshake as a full-duplex close
    /// signal. Ignoring it is what BoringSSL, NSS and OpenSSL all do, so
    /// refusing would break real peers — but it is still free work a
    /// peer can ask for, which is why the caller counts it.
    ignore,
    /// Any other warning-level alert. TLS 1.3 has no meaning for one, and
    /// §6.2's decode_error is the answer BoringSSL gives.
    refuse,
    /// Fatal, or a description we do not name: the connection is over.
    /// §6 makes every alert but the two above fatal anyway.
    peer_fatal,
};

pub fn disposition(self: Alert) Disposition {
    assert(self.level_wire == 1 or self.level_wire == 2);
    // Checked on the description rather than the level, matching the
    // file comment: in 1.3 a close_notify is a close whatever level byte
    // rode with it.
    if (self.isCloseNotify()) return .close;
    if (self.level_wire != @intFromEnum(Level.warning)) return .peer_fatal;
    if (self.description_wire == @intFromEnum(Description.user_canceled)) return .ignore;
    return .refuse;
}

pub fn encode(description: Description) [bytes]u8 {
    const level: Level = if (description == .close_notify or description == .user_canceled)
        .warning
    else
        .fatal;
    assert(@intFromEnum(level) == 1 or @intFromEnum(level) == 2);
    return .{ @intFromEnum(level), @intFromEnum(description) };
}

pub const ParseError = error{MalformedAlert};

pub const Error = ParseError || error{
    /// A warning-level alert TLS 1.3 gives no meaning to — anything but
    /// close_notify and user_canceled. Well-formed, so not
    /// `MalformedAlert`; §6.2's decode_error is what goes back, which is
    /// also what BoringSSL's `:BAD_ALERT:` carries.
    BadAlert,
};

pub fn parse(payload: []const u8) ParseError!Alert {
    if (payload.len != bytes) return error.MalformedAlert;
    if (payload[0] != 1 and payload[0] != 2) return error.MalformedAlert;
    return .{ .level_wire = payload[0], .description_wire = payload[1] };
}

test "disposition sorts an alert four ways, and the order is the point" {
    // The two that survive.
    try std.testing.expectEqual(Disposition.close, disposition(try parse(&.{ 1, 0 })));
    try std.testing.expectEqual(Disposition.ignore, disposition(try parse(&.{ 1, 90 })));

    // A warning level TLS 1.3 gives no meaning to. Not malformed —
    // understood, and declined.
    try std.testing.expectEqual(Disposition.refuse, disposition(try parse(&.{ 1, 40 })));
    try std.testing.expectEqual(Disposition.refuse, disposition(try parse(&.{ 1, 116 })));

    // Ordinary fatal alerts, named and unnamed.
    try std.testing.expectEqual(Disposition.peer_fatal, disposition(try parse(&.{ 2, 40 })));
    try std.testing.expectEqual(Disposition.peer_fatal, disposition(try parse(&.{ 2, 116 })));

    // The two orderings that carry the security of this function.
    //
    // `user_canceled` is tolerated *because* it is a warning. At fatal
    // level the peer is aborting, and reading that as "ignore" would let
    // a peer's abort be silently discarded — so the level check comes
    // before the description check.
    try std.testing.expectEqual(Disposition.peer_fatal, disposition(try parse(&.{ 2, 90 })));
    // close_notify is decided on the description alone, matching the
    // file comment. A fatal-level close_notify is still a close, and
    // this pins that it does not fall through to `peer_fatal`.
    try std.testing.expectEqual(Disposition.close, disposition(try parse(&.{ 2, 0 })));
}

test "close_notify round-trips and unknown descriptions stay readable" {
    const wire = encode(.close_notify);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0 }, &wire);
    const parsed = try parse(&wire);
    try std.testing.expect(parsed.isCloseNotify());
    try std.testing.expectEqual(Description.close_notify, parsed.description().?);

    // An alert code this library never names still parses; it reads as
    // null description and the caller treats it as fatal.
    const exotic = try parse(&.{ 2, 116 });
    try std.testing.expectEqual(@as(?Description, null), exotic.description());
    try std.testing.expect(!exotic.isCloseNotify());

    // Negative space: a level outside {1, 2} or a truncated alert.
    try std.testing.expectError(error.MalformedAlert, parse(&.{ 3, 0 }));
    try std.testing.expectError(error.MalformedAlert, parse(&.{1}));
}
