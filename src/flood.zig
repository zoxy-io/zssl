//! Two ceilings on work a peer can demand without making progress.
//!
//! Both are the same shape of attack: a record that is perfectly legal,
//! costs us a decryption, and returns nothing the embedder can act on.
//! Sent in a loop it is free for the sender and unbounded for us, and
//! nothing in RFC 8446 caps either one — §5.1 lets an application_data
//! record be empty, and §4.6.3 puts no limit on how many KeyUpdates a
//! peer may send. So the limits are policy, and the policy copied here
//! is BoringSSL's, because BoGo is what measures it: 32 of either, then
//! the connection ends (`kMaxEmptyRecords` and `kMaxKeyUpdates`, both
//! `uint8_t` 32, in `ssl/tls_record.cc` and `ssl/tls13_both.cc`).
//!
//! *Consecutive* is the whole of it. A peer that interleaves real
//! traffic is doing ordinary work and never approaches either ceiling,
//! which is why the counters reset on progress rather than accumulating
//! over a session — a long-lived connection may legitimately send far
//! more than 32 KeyUpdates in total. What resets what differs, and the
//! difference is not arbitrary: any record carrying content clears the
//! empty-record count because a byte arrived at all, while only
//! *application* bytes clear the KeyUpdate count, since a KeyUpdate
//! answered by another KeyUpdate is still no progress.
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
};

/// Both counters, and the only two places they move.
pub const Guard = struct {
    empty_records: u8 = 0,
    key_updates: u8 = 0,

    /// One record, already opened and stripped of its padding and
    /// content-type byte. `content_bytes` is what the peer actually
    /// delivered, so a record that was nothing but padding counts as
    /// empty — which is the point, since padding is exactly what makes
    /// an empty record cost something to open.
    pub fn observeRecord(self: *Guard, content_bytes: usize, content_type: record.ContentType) Error!void {
        assert(self.empty_records <= empty_records_max);
        assert(self.key_updates <= key_updates_max);
        if (content_bytes == 0) {
            if (self.empty_records == empty_records_max) return error.TooManyEmptyRecords;
            self.empty_records += 1;
            assert(self.empty_records <= empty_records_max);
            return;
        }
        self.empty_records = 0;
        if (content_type == .application_data) self.key_updates = 0;
        assert(self.empty_records == 0);
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

test "an empty application record does not reset the KeyUpdate count" {
    var guard: Guard = .{};
    for (0..key_updates_max) |_| try guard.observeKeyUpdate();
    try guard.observeRecord(0, .application_data);
    try std.testing.expectEqual(@as(u8, key_updates_max), guard.key_updates);
    try std.testing.expectError(error.TooManyKeyUpdates, guard.observeKeyUpdate());
}
