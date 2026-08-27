//! The RFC 8448 §3 handshake, replayed byte for byte.
//!
//! This file is the slice-1 oracle: the key ladder walks every secret the
//! trace prints, and record protection opens (and re-seals, where the
//! trace's nonces make it deterministic) every protected record in the
//! session. Agreement here is agreement with the RFC author's independent
//! implementation — the same class of evidence zoxy's Tier-0.5 gate buys
//! from `std.crypto.tls.Client`.

const std = @import("std");
const testing = std.testing;

const backend = @import("crypto/backend_openssl.zig");
const key_schedule = @import("key_schedule.zig");
const protect = @import("protect.zig");
const record = @import("record.zig");
const transcript_module = @import("transcript.zig");
const vectors = @import("rfc8448_vectors.zig");

const Schedule = key_schedule.KeySchedule(.aes_128_gcm_sha256);
const Transcript = transcript_module.Transcript(std.crypto.hash.sha2.Sha256);

test "the full §3 key ladder, byte for byte" {
    var schedule = Schedule.initEarly(null);
    try testing.expectEqualSlices(u8, &vectors.early_secret, &schedule.secret);

    var transcript: Transcript = .empty;
    transcript.update(&vectors.client_hello);
    transcript.update(&vectors.server_hello);

    var shared: [32]u8 = undefined;
    try backend.x25519Shared(&vectors.server_x25519_private, &vectors.client_x25519_public, &shared);
    try testing.expectEqualSlices(u8, &vectors.ecdhe_shared_secret, &shared);

    schedule.advanceToHandshake(&shared);
    try testing.expectEqualSlices(u8, &vectors.handshake_secret, &schedule.secret);

    const hello_hash = transcript.currentHash();
    const client_hs = schedule.deriveAt(.handshake, "c hs traffic", &hello_hash);
    const server_hs = schedule.deriveAt(.handshake, "s hs traffic", &hello_hash);
    try testing.expectEqualSlices(u8, &vectors.client_hs_traffic_secret, &client_hs);
    try testing.expectEqualSlices(u8, &vectors.server_hs_traffic_secret, &server_hs);

    const server_hs_keys = Schedule.trafficKeys(&server_hs);
    try testing.expectEqualSlices(u8, &vectors.server_hs_key, &server_hs_keys.key);
    try testing.expectEqualSlices(u8, &vectors.server_hs_iv, &server_hs_keys.iv);
    const client_hs_keys = Schedule.trafficKeys(&client_hs);
    try testing.expectEqualSlices(u8, &vectors.client_hs_key, &client_hs_keys.key);
    try testing.expectEqualSlices(u8, &vectors.client_hs_iv, &client_hs_keys.iv);

    transcript.update(&vectors.encrypted_extensions);
    transcript.update(&vectors.certificate);
    transcript.update(&vectors.certificate_verify);

    const server_finished_key = Schedule.finishedKey(&server_hs);
    try testing.expectEqualSlices(u8, &vectors.server_finished_key, &server_finished_key);
    const flight_hash = transcript.currentHash();
    const server_verify = Schedule.verifyData(&server_finished_key, &flight_hash);
    try testing.expectEqualSlices(u8, vectors.server_finished[4..], &server_verify);

    transcript.update(&vectors.server_finished);
    schedule.advanceToMaster();
    try testing.expectEqualSlices(u8, &vectors.master_secret, &schedule.secret);

    const finished_hash = transcript.currentHash();
    const client_ap = schedule.deriveAt(.master, "c ap traffic", &finished_hash);
    const server_ap = schedule.deriveAt(.master, "s ap traffic", &finished_hash);
    const exporter = schedule.deriveAt(.master, "exp master", &finished_hash);
    try testing.expectEqualSlices(u8, &vectors.client_ap_traffic_secret, &client_ap);
    try testing.expectEqualSlices(u8, &vectors.server_ap_traffic_secret, &server_ap);
    try testing.expectEqualSlices(u8, &vectors.exporter_master_secret, &exporter);

    const server_ap_keys = Schedule.trafficKeys(&server_ap);
    try testing.expectEqualSlices(u8, &vectors.server_ap_key, &server_ap_keys.key);
    try testing.expectEqualSlices(u8, &vectors.server_ap_iv, &server_ap_keys.iv);
    const client_ap_keys = Schedule.trafficKeys(&client_ap);
    try testing.expectEqualSlices(u8, &vectors.client_ap_key, &client_ap_keys.key);
    try testing.expectEqualSlices(u8, &vectors.client_ap_iv, &client_ap_keys.iv);

    const client_finished_key = Schedule.finishedKey(&client_hs);
    try testing.expectEqualSlices(u8, &vectors.client_finished_key, &client_finished_key);
    const client_verify = Schedule.verifyData(&client_finished_key, &finished_hash);
    try testing.expectEqualSlices(u8, vectors.client_finished[4..], &client_verify);

    transcript.update(&vectors.client_finished);
    const complete_hash = transcript.currentHash();
    const resumption_master = schedule.deriveAt(.master, "res master", &complete_hash);
    try testing.expectEqualSlices(u8, &vectors.resumption_master_secret, &resumption_master);

    // The trace's NewSessionTicket carries nonce 0x0000.
    const psk = Schedule.resumptionPsk(&resumption_master, &.{ 0, 0 });
    try testing.expectEqualSlices(u8, &vectors.resumption_psk, &psk);
}

test "record protection opens and re-seals every protected record" {
    var out: [record.wire_record_bytes_max]u8 = undefined;
    var wire: [record.wire_record_bytes_max]u8 = undefined;

    // Server handshake flight: EncryptedExtensions..Finished, sequence 0.
    var server_hs = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.server_hs_key, &vectors.server_hs_iv);
    defer server_hs.deinit();
    {
        const opened = try server_hs.open(&vectors.server_flight_record, &out);
        try testing.expectEqual(record.ContentType.handshake, opened.content_type);
        try testing.expectEqualSlices(u8, &vectors.server_flight_plaintext, out[0..opened.plaintext_bytes]);
    }
    {
        // Same key, fresh sequence: sealing the same plaintext must
        // reproduce the traced record exactly — AEAD determinism is the
        // property the whole replay strategy leans on.
        var sealer = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.server_hs_key, &vectors.server_hs_iv);
        defer sealer.deinit();
        const sealed = try sealer.seal(.handshake, &vectors.server_flight_plaintext, &wire);
        try testing.expectEqualSlices(u8, &vectors.server_flight_record, sealed);
    }

    // Client Finished under the client handshake key, sequence 0.
    var client_hs = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.client_hs_key, &vectors.client_hs_iv);
    defer client_hs.deinit();
    {
        const opened = try client_hs.open(&vectors.client_finished_record, &out);
        try testing.expectEqual(record.ContentType.handshake, opened.content_type);
        try testing.expectEqualSlices(u8, &vectors.client_finished_plaintext, out[0..opened.plaintext_bytes]);
    }

    // Server application key: NewSessionTicket at sequence 0, then the
    // application data record at sequence 1 — one protector, in order.
    var server_ap = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.server_ap_key, &vectors.server_ap_iv);
    defer server_ap.deinit();
    {
        const ticket = try server_ap.open(&vectors.ticket_record, &out);
        try testing.expectEqual(record.ContentType.handshake, ticket.content_type);
        try testing.expectEqualSlices(u8, &vectors.ticket_plaintext, out[0..ticket.plaintext_bytes]);
        const app = try server_ap.open(&vectors.server_app_record, &out);
        try testing.expectEqual(record.ContentType.application_data, app.content_type);
        try testing.expectEqualSlices(u8, &vectors.server_app_plaintext, out[0..app.plaintext_bytes]);
    }

    // Client application key: application data at 0, close_notify at 1.
    var client_ap = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.client_ap_key, &vectors.client_ap_iv);
    defer client_ap.deinit();
    {
        const app = try client_ap.open(&vectors.client_app_record, &out);
        try testing.expectEqual(record.ContentType.application_data, app.content_type);
        try testing.expectEqualSlices(u8, &vectors.client_app_plaintext, out[0..app.plaintext_bytes]);
        const alert = try client_ap.open(&vectors.client_alert_record, &out);
        try testing.expectEqual(record.ContentType.alert, alert.content_type);
        try testing.expectEqualSlices(u8, &vectors.client_alert_plaintext, out[0..alert.plaintext_bytes]);
    }
}

test "protection's negative space: tampering and sequence misuse fail closed" {
    var out: [record.wire_record_bytes_max]u8 = undefined;

    // One flipped ciphertext bit is an authentication failure.
    var protector = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.server_hs_key, &vectors.server_hs_iv);
    defer protector.deinit();
    var tampered = vectors.server_flight_record;
    tampered[record.header_bytes + 8] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, protector.open(&tampered, &out));

    // A protector whose sequence has advanced opens the same record with
    // the wrong nonce — the record is authentic, the state is not.
    var skewed = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.server_hs_key, &vectors.server_hs_iv);
    defer skewed.deinit();
    skewed.sequence = 1;
    try testing.expectError(error.AuthenticationFailed, skewed.open(&vectors.server_flight_record, &out));

    // A plaintext-type outer record is not for `open`.
    var not_protected: [record.header_bytes + 30]u8 = undefined;
    record.writeHeader(.{ .content_type = .handshake, .length = 30 }, not_protected[0..record.header_bytes]);
    @memset(not_protected[record.header_bytes..], 0);
    var fresh = try protect.Protector.init(.aes_128_gcm_sha256, &vectors.server_hs_key, &vectors.server_hs_iv);
    defer fresh.deinit();
    try testing.expectError(error.UnexpectedRecordType, fresh.open(&not_protected, &out));
}
