//! Three ceilings on work a peer can demand without making progress.
//!
//! All three are the same shape of attack: a record that is perfectly
//! legal, costs us a decryption, and returns nothing the embedder can
//! act on. Sent in a loop it is free for the sender and unbounded for
//! us, and RFC 8446 caps none of them — §5.1 lets an application_data
//! record be empty, §4.6.3 puts no limit on how many KeyUpdates a peer
//! may send, and §6.1 leaves `user_canceled` legal without saying what
//! to do with it. So the limits are policy, and the policy copied here
//! is BoringSSL's, because BoGo is what measures it: 32 empty records,
//! 32 KeyUpdates, 4 warning alerts (`kMaxEmptyRecords`, `kMaxKeyUpdates`
//! and `kMaxWarningAlerts` in `ssl/tls_record.cc` and
//! `ssl/tls13_both.cc`).
//!
//! *Consecutive* is the whole of it. A peer that interleaves real
//! traffic is doing ordinary work and never approaches any of them,
//! which is why the counters reset on progress rather than accumulating
//! over a session — a long-lived connection may legitimately send far
//! more than 32 KeyUpdates in total.
//!
//! What resets what differs, and none of it is arbitrary:
//!
//!   - an **alert** resets nothing. It carries content, so a naive
//!     "content is progress" rule would let the very records being
//!     counted refill the budget that bounds them;
//!   - any **other** record carrying content clears the empty-record and
//!     warning-alert counts, because a byte arrived that was not one of
//!     the things being bounded;
//!   - only **application** bytes clear the KeyUpdate count, since a
//!     KeyUpdate answered by another KeyUpdate is still no progress.
//!
//! This lives outside both handshakes because both need it and a limit
//! implemented twice is a limit that diverges — the same reason
//! session_keys.zig exists.

const std = @import("std");
const assert = std.debug.assert;
const record = @import("record.zig");

/// Consecutive empty records tolerated before the connection ends. The
/// 33rd is the one that fails, matching BoGo's `SendEmptyRecords-Pass`
/// (32) and `SendEmptyRecords` (33).
pub const empty_records_max: u8 = 32;

/// Consecutive KeyUpdates tolerated, on the same terms.
pub const key_updates_max: u8 = 32;

/// Consecutive warning-level `user_canceled` alerts tolerated. Four
/// rather than 32, which is BoringSSL's `kMaxWarningAlerts`: a peer that
/// means the signal sends it once, and BoGo's
/// `SendUserCanceledAlerts-TLS13` (4) and `-TooMany-TLS13` (5) sit
/// either side of the line.
pub const warning_alerts_max: u8 = 4;

pub const Error = error{
    /// More than `empty_records_max` records in a row carried no
    /// content. §6.2 has no alert for "you are wasting my time"; this
    /// answers unexpected_message, which is what BoringSSL sends.
    TooManyEmptyRecords,
    /// More than `key_updates_max` KeyUpdates in a row, with no
    /// application data between them. Distinct from
    /// `session_keys.Error.RotationsExhausted`, which is our own
    /// generation budget running out rather than a peer misbehaving.
    TooManyKeyUpdates,
    /// More than `warning_alerts_max` warning alerts in a row. Also
    /// unexpected_message, and also BoringSSL's answer.
    TooManyWarningAlerts,
};

/// The three counters, and the only three places they move.
pub const Guard = struct {
    empty_records: u8 = 0,
    key_updates: u8 = 0,
    warning_alerts: u8 = 0,

    /// One record, already opened and stripped of its padding and
    /// content-type byte. `content_bytes` is what the peer actually
    /// delivered, so a record that was nothing but padding counts as
    /// empty — which is the point, since padding is exactly what makes
    /// an empty record cost something to open.
    pub fn observeRecord(self: *Guard, content_bytes: usize, content_type: record.ContentType) Error!void {
        assert(self.empty_records <= empty_records_max);
        assert(self.key_updates <= key_updates_max);
        assert(self.warning_alerts <= warning_alerts_max);
        if (content_bytes == 0) {
            if (self.empty_records == empty_records_max) return error.TooManyEmptyRecords;
            self.empty_records += 1;
            assert(self.empty_records <= empty_records_max);
            return;
        }
        // An alert is never progress. BoringSSL reaches this decision by
        // returning from `ssl_process_alert` before its reset runs
        // (`ssl/tls_record.cc`), which is easy to read as an accident and
        // is not one: without it a peer alternating four warning alerts
        // with anything else would refill its own budget forever, and the
        // ceiling below would bound nothing.
        if (content_type == .alert) return;
        self.empty_records = 0;
        self.warning_alerts = 0;
        if (content_type == .application_data) self.key_updates = 0;
        assert(self.empty_records == 0);
    }

    /// One warning alert we are about to ignore. Counted because
    /// ignoring is itself the work a peer is buying.
    pub fn observeWarningAlert(self: *Guard) Error!void {
        assert(self.warning_alerts <= warning_alerts_max);
        if (self.warning_alerts == warning_alerts_max) return error.TooManyWarningAlerts;
        self.warning_alerts += 1;
        assert(self.warning_alerts >= 1);
        assert(self.warning_alerts <= warning_alerts_max);
    }

    /// One KeyUpdate, counted before it is acted on: processing it is
    /// the work being bounded.
    pub fn observeKeyUpdate(self: *Guard) Error!void {
        assert(self.key_updates <= key_updates_max);
        if (self.key_updates == key_updates_max) return error.TooManyKeyUpdates;
        self.key_updates += 1;
        assert(self.key_updates >= 1);
        assert(self.key_updates <= key_updates_max);
    }
};

test "empty records are bounded, and content resets the count" {
    var guard: Guard = .{};
    for (0..empty_records_max) |_| try guard.observeRecord(0, .application_data);
    try std.testing.expectError(error.TooManyEmptyRecords, guard.observeRecord(0, .application_data));
    // One byte of anything — here a handshake record — and the budget is
    // whole again.
    try guard.observeRecord(1, .handshake);
    try std.testing.expectEqual(@as(u8, 0), guard.empty_records);
    for (0..empty_records_max) |_| try guard.observeRecord(0, .application_data);
    try std.testing.expectError(error.TooManyEmptyRecords, guard.observeRecord(0, .application_data));
}

test "KeyUpdates are bounded, and only application data resets the count" {
    var guard: Guard = .{};
    for (0..key_updates_max) |_| try guard.observeKeyUpdate();
    try std.testing.expectError(error.TooManyKeyUpdates, guard.observeKeyUpdate());
    // A handshake record carrying content is not progress: the KeyUpdate
    // that arrived in it is precisely what we are counting.
    try guard.observeRecord(4, .handshake);
    try std.testing.expectEqual(@as(u8, key_updates_max), guard.key_updates);
    try std.testing.expectError(error.TooManyKeyUpdates, guard.observeKeyUpdate());
    // Application bytes are.
    try guard.observeRecord(1, .application_data);
    try std.testing.expectEqual(@as(u8, 0), guard.key_updates);
    try guard.observeKeyUpdate();
}

test "warning alerts are bounded, and application data resets the count" {
    var guard: Guard = .{};
    for (0..warning_alerts_max) |_| try guard.observeWarningAlert();
    try std.testing.expectError(error.TooManyWarningAlerts, guard.observeWarningAlert());
    try guard.observeRecord(1, .application_data);
    try std.testing.expectEqual(@as(u8, 0), guard.warning_alerts);
    try guard.observeWarningAlert();
}

test "an alert record is never progress" {
    // The reset this pins is what makes every ceiling here a ceiling. An
    // alert carries content, so a naive "content means progress" rule
    // would let a peer refill all three budgets with the very records
    // being counted.
    var guard: Guard = .{};
    for (0..warning_alerts_max) |_| try guard.observeWarningAlert();
    try guard.observeRecord(alert_bytes, .alert);
    try std.testing.expectEqual(@as(u8, warning_alerts_max), guard.warning_alerts);
    try std.testing.expectError(error.TooManyWarningAlerts, guard.observeWarningAlert());

    // The same record must not refill the other two either.
    var other: Guard = .{};
    for (0..empty_records_max) |_| try other.observeRecord(0, .application_data);
    for (0..key_updates_max) |_| try other.observeKeyUpdate();
    try other.observeRecord(alert_bytes, .alert);
    try std.testing.expectEqual(@as(u8, empty_records_max), other.empty_records);
    try std.testing.expectEqual(@as(u8, key_updates_max), other.key_updates);
    try std.testing.expectError(error.TooManyEmptyRecords, other.observeRecord(0, .application_data));
    try std.testing.expectError(error.TooManyKeyUpdates, other.observeKeyUpdate());
}

/// An alert is two bytes on the wire (§6.2); named so the tests above
/// read as "a well-formed alert" rather than "the number 2".
const alert_bytes = @import("alert.zig").bytes;

test "an empty application record does not reset the KeyUpdate count" {
    var guard: Guard = .{};
    for (0..key_updates_max) |_| try guard.observeKeyUpdate();
    try guard.observeRecord(0, .application_data);
    try std.testing.expectEqual(@as(u8, key_updates_max), guard.key_updates);
    try std.testing.expectError(error.TooManyKeyUpdates, guard.observeKeyUpdate());
}
