//! TLS alerts (RFC 8446 §6): two bytes, and in 1.3 the level byte carries
//! no information the description doesn't — every alert but close_notify
//! and user_canceled is fatal by definition, whatever level it claims.

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

pub fn encode(description: Description) [bytes]u8 {
    const level: Level = if (description == .close_notify or description == .user_canceled)
        .warning
    else
        .fatal;
    assert(@intFromEnum(level) == 1 or @intFromEnum(level) == 2);
    return .{ @intFromEnum(level), @intFromEnum(description) };
}

pub const ParseError = error{MalformedAlert};

pub fn parse(payload: []const u8) ParseError!Alert {
    if (payload.len != bytes) return error.MalformedAlert;
    if (payload[0] != 1 and payload[0] != 2) return error.MalformedAlert;
    return .{ .level_wire = payload[0], .description_wire = payload[1] };
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
