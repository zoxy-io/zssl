//! Slice 4's end-to-end: the production `ClientHandshake` against the
//! production `ServerHandshake` — both real machines, no test client.
//! Covers the full origination path zoxy needs for upstreams: SNI, ALPN,
//! leaf verification, tickets captured through the client's event
//! surface, resumption, §4.6.3 KeyUpdate in both directions with the
//! kTLS export tracking generations, and the client's HelloRetryRequest
//! handling — the retry it answers, the three §4.1.4 shapes it refuses,
//! and the PSK it drops on the way.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const ClientHandshake = @import("ClientHandshake.zig");
const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const cipher_suite = @import("cipher_suite.zig");
const record = @import("record.zig");
const flood = @import("flood.zig");
const alert = @import("alert.zig");
const backend = @import("crypto/backend_openssl.zig");
const key_schedule = @import("key_schedule.zig");
const protect = @import("protect.zig");
const client_hello_mod = @import("client_hello.zig");
const client_messages = @import("client_messages.zig");
const server_messages = @import("server_messages.zig");
const transcript = @import("transcript.zig");
const wire = @import("wire.zig");
const handshake = @import("handshake.zig");

const client_x25519_private = [_]u8{0x31} ** 31 ++ [_]u8{0x07};

/// A self-signed leaf carrying a 512-bit RSA key — smaller than any
/// modulus `verifyRsaPss` accepts, and the smallest openssl will mint.
/// Throwaway material, never a credential.
const rsa512_leaf_der = @embedFile("testdata/rsa512-leaf.der");
const server_key_share_private = [_]u8{0x93} ** 47 ++ [_]u8{0x0e};

const Buffers = struct {
    client_out: [2 * record.wire_record_bytes_max]u8 = undefined,
    server_out: [2 * record.wire_record_bytes_max]u8 = undefined,
    scratch: [2 * record.wire_record_bytes_max]u8 = undefined,
};

const TicketStore = struct {
    identity: [64]u8,
    identity_bytes: u8,
    psk: [cipher_suite.hash_bytes_max]u8,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age;
        const store: *TicketStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, store.identity[0..store.identity_bytes], identity)) return null;
        psk_out.* = store.psk;
        return .{ .psk_bytes = 32, .kind = .resumption };
    }
};

const Harness = struct {
    chain_storage: [Credentials.chain_bytes_max]u8,
    credentials: Credentials,
    server_reassembly: [8192]u8,
    flight: [Credentials.chain_bytes_max + 1024]u8,
    client_reassembly: [16384]u8,
    client_auth_flight: [Credentials.chain_bytes_max + 1024]u8,
    server: ServerHandshake,
    client: ClientHandshake,

    /// What a test varies. Everything defaults to the ordinary
    /// ECDSA-leaf, single-ALPN session the bulk of these tests want.
    const Options = struct {
        store: ?*TicketStore = null,
        resume_session: ?ClientHandshake.Resumption = null,
        /// What the server selects, or null to select nothing.
        server_alpn: ?[]const u8 = "http/1.1",
        client_alpn: []const []const u8 = &.{"http/1.1"},
        certificate_policy: ClientHandshake.CertificatePolicy = .leaf_signature,
        chain_verifier: ?ClientHandshake.ChainVerifier = null,
        /// The leaf the server presents. RSA draws a fresh PSS salt per
        /// signature, so it cannot run with deterministic nonces.
        leaf: enum { ecdsa_p256, ecdsa_p384, rsa_2048 } = .ecdsa_p256,
        /// The client's second key-exchange scalar, and the switch that
        /// lets it answer a HelloRetryRequest at all.
        retry_private: ?[backend.group_private_bytes_max]u8 = null,
        /// The server's group preference. Leaving x25519 out is what
        /// makes it retry a client that shares only x25519, which is
        /// every client this library builds.
        server_groups: []const u16 = &client_hello_mod.groups_supported,
        /// What the client advertises in `signature_algorithms`, and so
        /// what §4.4.3 lets the server sign with. Narrowing it is how a
        /// test reaches the "not offered" abort with a scheme this
        /// library is perfectly able to verify.
        client_verify_schemes: []const backend.SignatureScheme =
            &client_messages.signature_schemes_default,
        /// §4.4.2's signing set, narrowed. Null leaves the choice to the
        /// key, which is what almost every test here wants.
        server_signing_schemes: ?[]const u16 = null,
        /// §4.3.2: what the server asks of the client, and null for the
        /// ordinary one-sided handshake almost every test here wants.
        client_auth: ?ServerHandshake.ClientAuth = null,
        /// The client's own certificate, for answering that request.
        client_credentials: ?*const Credentials = null,
    };

    fn init(harness: *Harness, options: Options) !void {
        const store = options.store;
        const resume_session = options.resume_session;
        harness.credentials = switch (options.leaf) {
            .ecdsa_p256 => try Credentials.load(
                @embedFile("testdata/cert.pem"),
                @embedFile("testdata/key.pem"),
                &harness.chain_storage,
                true,
            ),
            .ecdsa_p384 => try Credentials.load(
                @embedFile("testdata/p384-cert.pem"),
                @embedFile("testdata/p384-key.pem"),
                &harness.chain_storage,
                true,
            ),
            .rsa_2048 => try Credentials.load(
                @embedFile("testdata/rsa2048-cert.pem"),
                @embedFile("testdata/rsa2048-key.pem"),
                &harness.chain_storage,
                false,
            ),
        };
        harness.server = ServerHandshake.init(&.{
            .credentials = &harness.credentials,
            .server_random = .{0x6d} ** 32,
            .key_share_private = server_key_share_private,
            .alpn = options.server_alpn,
            .groups = options.server_groups,
            .signing_schemes = options.server_signing_schemes,
            .client_auth = options.client_auth,
            .reassembly = &harness.server_reassembly,
            .flight = &harness.flight,
            .psk_lookup = if (store) |context| .{
                .context = context,
                .lookup = TicketStore.lookup,
            } else null,
        });
        harness.client = ClientHandshake.init(&.{
            .client_random = .{0x1a} ** 32,
            .x25519_private = client_x25519_private,
            .session_id = &(.{0x44} ** 32),
            .server_name = "spike.zoxy.test",
            .alpn_protocols = options.client_alpn,
            .certificate_policy = options.certificate_policy,
            .chain_verifier = options.chain_verifier,
            .resume_session = resume_session,
            .retry_key_share_private = options.retry_private,
            .verify_schemes = options.client_verify_schemes,
            .client_credentials = options.client_credentials,
            .client_auth_flight = if (options.client_credentials != null)
                &harness.client_auth_flight
            else
                &.{},
            .reassembly = &harness.client_reassembly,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.client.deinit();
        harness.server.deinit();
        harness.credentials.deinit();
    }

    /// Drive the handshake to `connected` on both machines, through a
    /// HelloRetryRequest if the server asks for one.
    fn connect(harness: *Harness, buffers: *Buffers) !void {
        const hello = harness.client.start(&buffers.client_out);
        var flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
        try testing.expectEqual(std.meta.activeTag(flight), .send);
        if (harness.server.state == .awaiting_retry_client_hello) {
            // §4.1.4 costs one extra round trip: what came back is the
            // retry and §D.4's CCS, and the flight proper is what the
            // second ClientHello earns.
            var second_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
            var second_bytes: usize = 0;
            var index: usize = 0;
            var count: u8 = 0;
            while (index < flight.send.len) : (count += 1) {
                try testing.expect(count < 4);
                const one = recordAt(flight.send, index);
                if (try harness.client.handleRecord(one, &buffers.scratch)) |event| {
                    try testing.expectEqual(std.meta.activeTag(event), .send);
                    // Copied out rather than held as a slice: the retry
                    // flight is two records, the second hello comes back
                    // on the first of them, and the `handleRecord` that
                    // takes the second is free to write over `scratch` —
                    // which is where these bytes live until they are
                    // somewhere else.
                    @memcpy(second_storage[0..event.send.len], event.send);
                    second_bytes = event.send.len;
                }
                index += one.len;
            }
            try testing.expect(second_bytes >= 1);
            index = 0;
            count = 0;
            var answered: ?ServerHandshake.Event = null;
            while (index < second_bytes) : (count += 1) {
                try testing.expect(count < 4);
                const one = recordAt(second_storage[0..second_bytes], index);
                if (try harness.server.handleRecord(one, &buffers.server_out)) |event| {
                    answered = event;
                }
                index += one.len;
            }
            flight = answered orelse return error.TestExpectedFlight;
            try testing.expectEqual(std.meta.activeTag(flight), .send);
        }

        var reply_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
        var reply_bytes: usize = 0;
        var index: usize = 0;
        var count: u8 = 0;
        while (index < flight.send.len) : (count += 1) {
            try testing.expect(count < 8);
            const one = recordAt(flight.send, index);
            if (try harness.client.handleRecord(one, &buffers.scratch)) |event| switch (event) {
                .connected => |bytes| {
                    @memcpy(reply_storage[0..bytes.len], bytes);
                    reply_bytes = bytes.len;
                },
                else => return error.TestUnexpectedResult,
            };
            index += one.len;
        }
        try testing.expect(reply_bytes >= 1);
        try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);

        index = 0;
        count = 0;
        var final: ?ServerHandshake.Event = null;
        while (index < reply_bytes) : (count += 1) {
            try testing.expect(count < 8);
            const one = recordAt(reply_storage[0..reply_bytes], index);
            if (try harness.server.handleRecord(one, &buffers.server_out)) |event| final = event;
            index += one.len;
        }
        try testing.expectEqual(std.meta.activeTag(final.?), .connected);
        try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
    }
};

fn recordAt(bytes: []const u8, index: usize) []const u8 {
    const length = std.mem.readInt(u16, bytes[index + 3 ..][0..2], .big);
    return bytes[index..][0 .. record.header_bytes + length];
}

/// The last record in a run of them. A client flight may lead with §D.4's
/// compatibility CCS, so a test after the handshake message walks to the
/// end rather than assuming which record it is.
fn lastRecord(bytes: []const u8) []const u8 {
    assert(bytes.len >= record.header_bytes);
    var index: usize = 0;
    var last: []const u8 = &.{};
    while (index < bytes.len) {
        last = recordAt(bytes, index);
        index += last.len;
    }
    assert(index == bytes.len);
    return last;
}

fn expectExportAgreement(server: *const ServerHandshake, client: *const ClientHandshake) !void {
    const server_transmit = server.exportKeyMaterial(.transmit);
    const client_receive = client.exportKeyMaterial(.receive);
    try testing.expectEqualSlices(u8, server_transmit.key[0..server_transmit.key_bytes], client_receive.key[0..client_receive.key_bytes]);
    try testing.expectEqualSlices(u8, &server_transmit.static_iv, &client_receive.static_iv);
    try testing.expectEqual(server_transmit.next_sequence, client_receive.next_sequence);
    const server_receive = server.exportKeyMaterial(.receive);
    const client_transmit = client.exportKeyMaterial(.transmit);
    try testing.expectEqualSlices(u8, server_receive.key[0..server_receive.key_bytes], client_transmit.key[0..client_transmit.key_bytes]);
    try testing.expectEqual(server_receive.next_sequence, client_transmit.next_sequence);
}

/// Issue one NewSessionTicket over a connected pair and hand back what
/// a second session needs to resume on it: `store` is filled in for the
/// server's `psk_lookup`, and the `Resumption` is the client's half.
///
/// Both ends derive the PSK from their own `resumption_master` and never
/// exchange it, so the agreement checked here is the whole point of the
/// derivation — a helper that took one side's copy and handed it to the
/// other would test nothing.
fn issueTicket(
    harness: *Harness,
    buffers: *Buffers,
    store: *TicketStore,
) !ClientHandshake.Resumption {
    var psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const server_psk = harness.server.resumptionPsk(&.{0x0a}, &psk_buffer);
    @memset(&store.psk, 0);
    @memcpy(store.psk[0..server_psk.len], server_psk);
    @memcpy(store.identity[0..13], "sealed-by-us!");
    store.identity_bytes = 13;
    const sealed = try harness.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 0x5eed,
        .ticket_nonce = &.{0x0a},
        .ticket = "sealed-by-us!",
        // Advertised so the *production* client's `checkTicketExtensions`
        // meets §4.6.1's `early_data` — an extension it acts on nothing
        // about and must still parse, which is finding 7's rule. The
        // client cannot offer 0-RTT yet, so tolerating it is the whole
        // of what this proves, and every resumption test downstream of
        // this helper now carries it.
        .early_data_bytes_max = 16384,
    }, &buffers.server_out);
    const ticket_event = (try harness.client.handleRecord(sealed, &buffers.scratch)).?;
    try testing.expectEqual(std.meta.activeTag(ticket_event), .ticket);
    try testing.expectEqual(@as(u32, 3600), ticket_event.ticket.lifetime_s);
    // §4.6.1's limit reaches the embedder, which is the only way it can
    // ever decide to offer 0-RTT next time: what a client may send is a
    // fact about the ticket, and the ticket is the embedder's to store.
    try testing.expectEqual(@as(?u32, 16384), ticket_event.ticket.early_data_bytes_max);
    var resumption: ClientHandshake.Resumption = .{
        .identity = "sealed-by-us!",
        .obfuscated_age = ticket_event.ticket.age_add,
        .psk = undefined,
        .psk_bytes = 32,
    };
    var client_psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const client_psk = harness.client.resumptionPsk(ticket_event.ticket.nonce, &client_psk_buffer);
    @memset(&resumption.psk, 0);
    @memcpy(resumption.psk[0..client_psk.len], client_psk);
    try testing.expectEqualSlices(u8, server_psk, client_psk);
    return resumption;
}

test "production client ↔ server: handshake, data, ticket capture, resumption" {
    var buffers: Buffers = .{};

    // Session one, full handshake with leaf verification and ALPN.
    var first: Harness = undefined;
    try first.init(.{});
    defer first.deinit();
    try first.connect(&buffers);
    try testing.expect(first.client.peer.verified);
    try testing.expectEqualSlices(u8, "http/1.1", first.client.alpnSelected().?);
    try testing.expect(!first.client.resumed);
    try testing.expect(!first.server.resumed);

    // Application data in both directions.
    const ping = try first.client.sendApplicationData("ping from origin client", &buffers.client_out);
    const ping_event = (try first.server.handleRecord(ping, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "ping from origin client", ping_event.application_data);
    const pong = try first.server.sendApplicationData("pong", &buffers.server_out);
    const pong_event = (try first.client.handleRecord(pong, &buffers.scratch)).?;
    try testing.expectEqualSlices(u8, "pong", pong_event.application_data);

    // A ticket travels server → client through the event surface; the
    // client derives the PSK for it from its own resumption_master.
    var store: TicketStore = undefined;
    const resumption = try issueTicket(&first, &buffers, &store);

    // Clean close, server first this time.
    const close_record = try first.server.sendClose(&buffers.server_out);
    const close_event = (try first.client.handleRecord(close_record, &buffers.scratch)).?;
    try testing.expectEqual(std.meta.activeTag(close_event), .closed);

    // Session two: resumed on the captured ticket, no certificate leg.
    var second: Harness = undefined;
    try second.init(.{ .store = &store, .resume_session = resumption });
    defer second.deinit();
    try second.connect(&buffers);
    try testing.expect(second.server.resumed);
    try testing.expect(second.client.resumed);
    try testing.expect(!second.client.peer.verified);
    const echo = try second.client.sendApplicationData("resumed", &buffers.client_out);
    const echo_event = (try second.server.handleRecord(echo, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "resumed", echo_event.application_data);
}

test "KeyUpdate both ways: generations rotate and the kTLS export tracks them" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);
    try expectExportAgreement(&harness.server, &harness.client);
    const before = harness.client.exportKeyMaterial(.transmit);

    // Client-initiated, with a rotation demanded of the server too.
    const update = try harness.client.sendKeyUpdate(true, &buffers.client_out);
    const update_event = (try harness.server.handleRecord(update, &buffers.server_out)).?;
    try testing.expectEqual(std.meta.activeTag(update_event), .send);
    // Null, not an event: the client rotated and had nothing to say
    // back, which `update_requested` on our side does not ask for.
    try testing.expect(try harness.client.handleRecord(update_event.send, &buffers.scratch) == null);

    // Every direction moved to generation 1 and both sides agree.
    const after = harness.client.exportKeyMaterial(.transmit);
    try testing.expect(!std.mem.eql(u8, before.key[0..before.key_bytes], after.key[0..after.key_bytes]));
    try expectExportAgreement(&harness.server, &harness.client);

    // Traffic still flows under the new generation, both ways.
    const ping = try harness.client.sendApplicationData("post-update ping", &buffers.client_out);
    const ping_event = (try harness.server.handleRecord(ping, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "post-update ping", ping_event.application_data);
    const pong = try harness.server.sendApplicationData("post-update pong", &buffers.server_out);
    const pong_event = (try harness.client.handleRecord(pong, &buffers.scratch)).?;
    try testing.expectEqualSlices(u8, "post-update pong", pong_event.application_data);

    // Server-initiated, no rotation requested back: only its transmit
    // side and the client's receive side move.
    const quiet_update = try harness.server.sendKeyUpdate(false, &buffers.server_out);
    try testing.expect(try harness.client.handleRecord(quiet_update, &buffers.scratch) == null);
    try expectExportAgreement(&harness.server, &harness.client);
    const again = try harness.server.sendApplicationData("gen2", &buffers.server_out);
    const again_event = (try harness.client.handleRecord(again, &buffers.scratch)).?;
    try testing.expectEqualSlices(u8, "gen2", again_event.application_data);
}

/// Re-derive the server→client handshake protector from public wire
/// bytes plus the client's own private key — independently of either
/// machine's internals, which is what lets a test forge a server flight.
fn serverFlightProtector(
    client_private: *const [32]u8,
    client_hello_record: []const u8,
    server_hello_record: []const u8,
) !protect.Protector {
    const Schedule = key_schedule.KeySchedule(.aes_128_gcm_sha256);
    const server_hello = server_hello_record[record.header_bytes..];
    // The ServerHello's key_share sits at a fixed offset for our own
    // encoder: 4 header + 2 version + 32 random + 1 echo length + echo +
    // 2 suite + 1 compression + 2 extensions length + 2 type + 2 length
    // + 2 group + 2 key length.
    const echo_bytes = server_hello[38];
    const share_at = 39 + @as(usize, echo_bytes) + 3 + 2 + 2 + 2 + 2 + 2;
    const server_public = server_hello[share_at..][0..32];
    var shared: [32]u8 = undefined;
    try backend.x25519Shared(client_private, server_public, &shared);

    var script: transcript.Transcript(std.crypto.hash.sha2.Sha256) = .empty;
    script.update(client_hello_record[record.header_bytes..]);
    script.update(server_hello);
    var schedule = Schedule.initEarly(null);
    schedule.advanceToHandshake(&shared);
    const secret = schedule.deriveAt(.handshake, "s hs traffic", &script.currentHash());
    const keys = Schedule.trafficKeys(&secret);
    return protect.Protector.init(.aes_128_gcm_sha256, &keys.key, &keys.iv);
}

test "a hostile server flight errors rather than panicking" {
    // Every shape below once reached an assertion on attacker-shaped
    // input. They must be protocol errors.
    const Shape = struct {
        kind: enum { verify_without_certificate, duplicate_certificate, undersized_rsa_leaf },
        expected: anyerror,
    };
    const shapes = [_]Shape{
        // CertificateVerify with nothing to verify against.
        .{ .kind = .verify_without_certificate, .expected = error.UnexpectedMessage },
        // A second Certificate overwriting the first.
        .{ .kind = .duplicate_certificate, .expected = error.UnexpectedMessage },
        // An RSA leaf whose modulus is smaller than any size we verify.
        // `captureLeaf` only sanity-floors the encoded key, so the length
        // that decides this is the peer's; the size gate lives in
        // `verifyRsaPss` and must *refuse*, never assert.
        .{ .kind = .undersized_rsa_leaf, .expected = error.BadCertificate },
    };
    for (shapes) |shape| {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();

        // Drive the real handshake far enough that the client holds the
        // server's handshake keys, stopping before the protected flight.
        const hello = harness.client.start(&buffers.client_out);
        const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);
        try testing.expectEqual(ClientHandshake.State.awaiting_encrypted_extensions, harness.client.state);

        // Forge a flight under the genuine handshake keys.
        var forger = try serverFlightProtector(
            &client_x25519_private,
            hello,
            server_hello_record,
        );
        defer forger.deinit();
        var plaintext: [4096]u8 = undefined;
        var used: usize = 0;
        const extensions = server_messages.encryptedExtensions(plaintext[used..], "http/1.1", false);
        used += extensions.len;
        switch (shape.kind) {
            .verify_without_certificate => {
                // CertificateVerify with nothing to verify against.
                const forged = server_messages.certificateVerify(plaintext[used..], 0x0403, &(.{0x30} ** 70));
                used += forged.len;
            },
            .duplicate_certificate => {
                const chain = harness.credentials.chain();
                const first = server_messages.certificateChain(plaintext[used..], chain);
                used += first.len;
                const second = server_messages.certificateChain(plaintext[used..], chain);
                used += second.len;
            },
            .undersized_rsa_leaf => {
                const leaf: []const u8 = rsa512_leaf_der;
                const certificate = server_messages.certificateChain(plaintext[used..], &.{leaf});
                used += certificate.len;
                // rsa_pss_rsae_sha256 over a 512-bit modulus: the scheme
                // and the key kind agree, so this reaches the size gate
                // rather than being turned away by the kind check.
                const forged = server_messages.certificateVerify(plaintext[used..], 0x0804, &(.{0x30} ** 64));
                used += forged.len;
            },
        }
        var forged_record: [record.wire_record_bytes_max]u8 = undefined;
        const sealed = try forger.seal(.handshake, plaintext[0..used], &forged_record);
        try testing.expectError(
            shape.expected,
            harness.client.handleRecord(sealed, &buffers.scratch),
        );
        try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
    }
}

/// Frame a HelloRetryRequest naming `group`, ready to feed to a client.
fn retryRecord(out: []u8, group: u16) []const u8 {
    var message_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = server_messages.helloRetryRequest(
        &message_buffer,
        &(.{0x44} ** 32),
        .aes_128_gcm_sha256,
        group,
    );
    record.writeHeader(
        .{ .content_type = .handshake, .length = @intCast(retry.len) },
        out[0..record.header_bytes],
    );
    @memcpy(out[record.header_bytes..][0..retry.len], retry);
    return out[0 .. record.header_bytes + retry.len];
}

test "§4.1.4: a retry naming the group we already shared is illegal" {
    // The shape §4.1.4 calls out by name: "the client MUST abort ... if
    // the HelloRetryRequest would not result in any change in the
    // ClientHello". We shared x25519, so being asked for x25519 again is
    // a server that would loop us. Answering `HandshakeFailure` — which
    // this client did for *every* retry when it could answer none — said
    // "I cannot", where the truth is "you may not".
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .retry_private = .{0x71} ** 48 });
    defer harness.deinit();
    _ = harness.client.start(&buffers.client_out);

    var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = retryRecord(&wire_buffer, client_hello_mod.group_x25519);
    try testing.expectError(
        error.IllegalRetry,
        harness.client.handleRecord(retry, &buffers.scratch),
    );
    try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
}

test "§4.1.4: a retry into a group we advertised produces a second hello" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .retry_private = .{0x71} ** 48 });
    defer harness.deinit();
    const first = harness.client.start(&buffers.client_out);
    const first_hello = try client_hello_mod.parse(first[record.header_bytes..]);
    // The offer that makes a retry legal at all: three groups advertised,
    // one share. A client that advertises only what it shares cannot be
    // retried, which is a way of being untestable (DESIGN.md §1).
    try testing.expect(first_hello.supportsGroup(client_hello_mod.group_secp256r1));
    try testing.expectEqual(@as(?[]const u8, null), first_hello.keyShareFor(client_hello_mod.group_secp256r1));

    var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = retryRecord(&wire_buffer, client_hello_mod.group_secp256r1);
    const event = (try harness.client.handleRecord(retry, &buffers.scratch)).?;
    try testing.expectEqual(std.meta.activeTag(event), .send);
    try testing.expectEqual(ClientHandshake.State.awaiting_server_hello, harness.client.state);

    // The second hello carries a share for the group we were sent to,
    // and an uncompressed SEC1 point at that — §4.2.8.2's only encoding.
    const hello_record = lastRecord(event.send);
    try testing.expectEqual(record.ContentType.handshake, try contentTypeOf(hello_record));
    const second = try client_hello_mod.parse(hello_record[record.header_bytes..]);
    const share = second.keyShareFor(client_hello_mod.group_secp256r1) orelse
        return error.TestExpectedShare;
    try testing.expectEqual(@as(usize, 65), share.len);
    try testing.expectEqual(@as(u8, 0x04), share[0]);
    // And the old one is gone: two shares would re-open the loop §4.1.4
    // closes.
    try testing.expectEqual(@as(?[]const u8, null), second.keyShareFor(client_hello_mod.group_x25519));
}

test "a PSK whose hash is not the retry's suite is dropped, and a selected one refused" {
    // Two rules meeting. §4.2.11: a client "SHOULD NOT offer any
    // pre-shared keys associated with a hash other than that of the
    // selected cipher suite", and a ticket's PSK is a hash long by
    // §4.6.1's derivation — so a 48-byte PSK against a retry naming
    // AES-128-GCM-SHA256 has nowhere to go and stays behind.
    //
    // And then the hole that guards. The ServerHello parser gated
    // `pre_shared_key` on the *config* holding a resumption, which
    // stopped meaning "this hello offered one" the moment a retry could
    // change the hello. A server answering with `selected_identity`
    // anyway would set `resumed`, and `resumed` is what tells
    // `completeHandshake` a certificate was not required. §4.2.11
    // forbids selecting an identity the client did not offer, so this is
    // the RFC's refusal as much as it is ours.
    //
    // The guard outlived the reason it was written: CH2 now carries the
    // PSK whenever the hashes agree (the test below), and this is the
    // case where it still does not.
    var buffers: Buffers = .{};
    var store: TicketStore = .{
        .identity = undefined,
        .identity_bytes = 6,
        .psk = .{0x5e} ** cipher_suite.hash_bytes_max,
    };
    @memcpy(store.identity[0..6], "ticket");
    const resumption: ClientHandshake.Resumption = .{
        .identity = store.identity[0..6],
        .obfuscated_age = 0,
        .psk = store.psk,
        .psk_bytes = 48, // SHA-384; the retry below names SHA-256.
    };
    var harness: Harness = undefined;
    try harness.init(.{ .retry_private = .{0x71} ** 48, .resume_session = resumption });
    defer harness.deinit();
    _ = harness.client.start(&buffers.client_out);

    // Retry into a group we advertised: CH2 goes out without the PSK.
    var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = retryRecord(&wire_buffer, client_hello_mod.group_secp256r1);
    const event = (try harness.client.handleRecord(retry, &buffers.scratch)).?;
    try testing.expectEqual(std.meta.activeTag(event), .send);
    try testing.expect(!harness.client.resumed);
    try testing.expect(!harness.client.psk_offered);
    try testing.expectEqual(
        @as(?[]const u8, null),
        (try client_hello_mod.parse(lastRecord(event.send)[record.header_bytes..])).pre_shared_key_wire,
    );

    // Now answer with a ServerHello that selects identity 0 anyway.
    var hello_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    var b = wire.Builder.init(&hello_buffer);
    const message = handshake.beginMessage(&b, .server_hello);
    b.putU16(0x0303);
    b.putSlice(&(.{0x2b} ** 32));
    b.putByte(32);
    b.putSlice(&(.{0x44} ** 32));
    b.putU16(@intFromEnum(cipher_suite.CipherSuite.aes_128_gcm_sha256));
    b.putByte(0);
    const extensions = b.markU16();
    b.putU16(43); // supported_versions
    const versions = b.markU16();
    b.putU16(0x0304);
    b.patchU16(versions);
    b.putU16(41); // pre_shared_key, for an identity CH2 never offered
    const psk_ext = b.markU16();
    b.putU16(0);
    b.patchU16(psk_ext);
    b.patchU16(extensions);
    handshake.endMessage(&b, message);
    const hello = b.written();

    var framed: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
    record.writeHeader(
        .{ .content_type = .handshake, .length = @intCast(hello.len) },
        framed[0..record.header_bytes],
    );
    @memcpy(framed[record.header_bytes..][0..hello.len], hello);
    try testing.expectError(
        error.BadServerHello,
        harness.client.handleRecord(framed[0 .. record.header_bytes + hello.len], &buffers.scratch),
    );
    try testing.expect(!harness.client.resumed);
}

test "§4.4.1: a PSK crosses a retry, bound to the reconstructed transcript" {
    // The binder on a second ClientHello is not over the second
    // ClientHello. §4.2.11.2 asks for Transcript-Hash(Truncate(CH)), and
    // after a HelloRetryRequest §4.4.1 has already put message_hash(CH1)
    // and the retry into that transcript — so the hash covers three
    // things and the truncation is only the last of them.
    //
    // Recomputed here from the wire bytes with `std.crypto` directly,
    // not from the ladder that produced it. Agreement between two
    // derivations is the check; one of them going through
    // `Transcript.hashWith` would only prove the function equals itself.
    var buffers: Buffers = .{};
    const psk = [_]u8{0x5e} ** 32;
    var store: TicketStore = .{
        .identity = undefined,
        .identity_bytes = 6,
        .psk = .{0x5e} ** cipher_suite.hash_bytes_max,
    };
    @memcpy(store.identity[0..6], "ticket");
    const resumption: ClientHandshake.Resumption = .{
        .identity = store.identity[0..6],
        .obfuscated_age = 0,
        .psk = store.psk,
        .psk_bytes = 32, // SHA-256, which is what the retry names.
    };
    var harness: Harness = undefined;
    try harness.init(.{ .retry_private = .{0x71} ** 48, .resume_session = resumption });
    defer harness.deinit();
    const first = harness.client.start(&buffers.client_out);
    const ch1 = lastRecord(first)[record.header_bytes..];

    var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = retryRecord(&wire_buffer, client_hello_mod.group_secp256r1);
    const hrr = retry[record.header_bytes..];
    const event = (try harness.client.handleRecord(retry, &buffers.scratch)).?;
    try testing.expectEqual(std.meta.activeTag(event), .send);
    try testing.expect(harness.client.psk_offered);

    // CH2 carries the same identity CH1 did.
    const ch2 = lastRecord(event.send)[record.header_bytes..];
    const second = try client_hello_mod.parse(ch2);
    const offer = (try client_hello_mod.parsePskOffer(&second)) orelse
        return error.TestExpectedPskOffer;
    try testing.expectEqual(@as(u8, 1), offer.count);
    try testing.expectEqualSlices(u8, "ticket", offer.identities[0]);

    // §4.4.1's reconstruction, spelled out: the synthetic message_hash
    // message — type 254, a u24 length, and the hash of CH1 — then the
    // HelloRetryRequest, then the truncated CH2.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var ch1_hash: [32]u8 = undefined;
    Sha256.hash(ch1, &ch1_hash, .{});
    var reconstructed = Sha256.init(.{});
    reconstructed.update(&[_]u8{ 254, 0, 0, 32 });
    reconstructed.update(&ch1_hash);
    reconstructed.update(hrr);
    reconstructed.update(ch2[0 .. ch2.len - offer.binders_section_bytes]);
    var digest: [32]u8 = undefined;
    reconstructed.final(&digest);

    var schedule = key_schedule.KeySchedule(.aes_128_gcm_sha256).initEarly(&psk);
    defer schedule.wipe();
    const expected = schedule.pskBinder(.resumption, &digest);
    try testing.expectEqualSlices(u8, &expected, offer.binders[0]);

    // And the truncation alone — what the binder used to be over — is a
    // different value, so the test above could not pass by accident.
    var truncated_hash: [32]u8 = undefined;
    Sha256.hash(ch2[0 .. ch2.len - offer.binders_section_bytes], &truncated_hash, .{});
    const wrong = schedule.pskBinder(.resumption, &truncated_hash);
    try testing.expect(!std.mem.eql(u8, &wrong, offer.binders[0]));
}

test "§4.1.4: a second retry, and a retry we hold no scalar for" {
    var buffers: Buffers = .{};
    // One retry is the limit — "the client MUST abort ... with an
    // unexpected_message alert" on a second.
    {
        var harness: Harness = undefined;
        try harness.init(.{ .retry_private = .{0x71} ** 48 });
        defer harness.deinit();
        _ = harness.client.start(&buffers.client_out);
        var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
        const first = retryRecord(&wire_buffer, client_hello_mod.group_secp256r1);
        _ = try harness.client.handleRecord(first, &buffers.scratch);
        var second_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
        const again = retryRecord(&second_buffer, client_hello_mod.group_secp384r1);
        try testing.expectError(
            error.UnexpectedMessage,
            harness.client.handleRecord(again, &buffers.scratch),
        );
    }

    // Without retry entropy the structural refusal stands, which is the
    // behaviour every embedder had before this config field existed.
    // `HandshakeFailure` and not `IllegalRetry`: the retry is legal, we
    // simply cannot answer it without inventing randomness §1 forbids.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        _ = harness.client.start(&buffers.client_out);
        var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
        const retry = retryRecord(&wire_buffer, client_hello_mod.group_secp256r1);
        try testing.expectError(
            error.HandshakeFailure,
            harness.client.handleRecord(retry, &buffers.scratch),
        );
    }
}

/// A `chain_verifier` that records what it was shown and answers with a
/// verdict the test chose in advance.
const ChainSpy = struct {
    verdict: bool,
    calls: u8 = 0,
    entries: usize = 0,
    leaf_bytes: usize = 0,
    malformed: bool = false,

    fn verify(context: *anyopaque, chain: ClientHandshake.CertificateList) bool {
        const spy: *ChainSpy = @ptrCast(@alignCast(context));
        spy.calls += 1;
        var it = chain.iterator();
        while (it.next() catch {
            spy.malformed = true;
            return false;
        }) |entry| {
            if (spy.entries == 0) spy.leaf_bytes = entry.len;
            spy.entries += 1;
        }
        return spy.verdict;
    }

    fn verifier(spy: *ChainSpy) ClientHandshake.ChainVerifier {
        return .{ .context = spy, .verify = ChainSpy.verify };
    }
};

test "end to end through a HelloRetryRequest: working keys, data, agreeing exports" {
    // The claim the client's HelloRetryRequest support makes and that no
    // in-tree oracle checked: the group we are retried *into* really
    // derives working keys against a real peer. BoGo checked it, so
    // `zig build test` would have stayed green if it broke.
    //
    // A server preferring curves our client does not share is the whole
    // trick, and the reason this needed a config knob before it could be
    // a test: with x25519 in its list the server takes the share it was
    // given and never retries, and every client this library builds
    // shares x25519.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{
        .server_groups = &.{ client_hello_mod.group_secp256r1, client_hello_mod.group_secp384r1 },
        .retry_private = .{0x71} ** 48,
    });
    defer harness.deinit();
    try harness.connect(&buffers);

    // A retry really happened — `connect` would have taken the straight
    // path in silence — and both ends landed on the same group.
    try testing.expect(harness.client.retried);
    try testing.expectEqual(backend.Group.secp256r1, harness.server.key_share_group);
    try testing.expectEqual(client_hello_mod.group_secp256r1, harness.client.share_group);
    try testing.expect(harness.client.peer.verified);
    try testing.expectEqualSlices(u8, "http/1.1", harness.client.alpnSelected().?);

    // Working keys in both directions, and one derivation on each side.
    const ping = try harness.client.sendApplicationData("over the retry", &buffers.client_out);
    const ping_event = (try harness.server.handleRecord(ping, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "over the retry", ping_event.application_data);
    const pong = try harness.server.sendApplicationData("and back", &buffers.server_out);
    const pong_event = (try harness.client.handleRecord(pong, &buffers.scratch)).?;
    try testing.expectEqualSlices(u8, "and back", pong_event.application_data);
    try expectExportAgreement(&harness.server, &harness.client);
}

test "end to end: a resumed session crosses a HelloRetryRequest" {
    // `retry_private` and `resume_session` in one handshake against a
    // real server — the case that would have caught the `resumed`
    // authentication bypass, where a hello that had dropped its PSK
    // could still be answered with a `selected_identity`.
    //
    // It also drives §4.4.1's binder from both ends at once: the client
    // computes it over message_hash(CH1) + the retry + the truncated
    // CH2, and the server verifies it against a transcript it built
    // independently. The unit tests check each half against a hand-rolled
    // hash; this checks the two against each other.
    var buffers: Buffers = .{};
    var first: Harness = undefined;
    try first.init(.{});
    defer first.deinit();
    try first.connect(&buffers);
    var store: TicketStore = undefined;
    const resumption = try issueTicket(&first, &buffers, &store);

    var second: Harness = undefined;
    try second.init(.{
        .store = &store,
        .resume_session = resumption,
        .server_groups = &.{client_hello_mod.group_secp256r1},
        .retry_private = .{0x71} ** 48,
    });
    defer second.deinit();
    try second.connect(&buffers);
    try testing.expect(second.client.retried);
    try testing.expect(second.client.psk_offered);
    try testing.expect(second.server.resumed);
    try testing.expect(second.client.resumed);
    // Resumed means the PSK authenticated the session: no certificate
    // leg travelled, and none was verified.
    try testing.expect(!second.client.peer.verified);
    const echo = try second.client.sendApplicationData("resumed over a retry", &buffers.client_out);
    const echo_event = (try second.server.handleRecord(echo, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "resumed over a retry", echo_event.application_data);
    try expectExportAgreement(&second.server, &second.client);
}

test "the chain verifier is shown the peer's chain, leaf first" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    var spy: ChainSpy = .{ .verdict = true };
    try harness.init(.{ .chain_verifier = spy.verifier() });
    defer harness.deinit();
    try harness.connect(&buffers);

    try testing.expectEqual(@as(u8, 1), spy.calls);
    try testing.expect(!spy.malformed);
    try testing.expectEqual(@as(usize, 1), spy.entries);
    // The leaf it saw is the fixture the server actually holds, not a
    // slice that merely had a plausible length.
    const leaf = harness.credentials.certificates[0];
    try testing.expectEqual(leaf.len, spy.leaf_bytes);
    const certificate: std.crypto.Certificate = .{ .buffer = leaf, .index = 0 };
    const parsed = try certificate.parse();
    try testing.expectEqual(
        std.crypto.Certificate.Parsed.PubKeyAlgo.X9_62_id_ecPublicKey,
        std.meta.activeTag(parsed.pub_key_algo),
    );
}

test "a chain the embedder refuses fails the handshake" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    var spy: ChainSpy = .{ .verdict = false };
    try harness.init(.{ .chain_verifier = spy.verifier() });
    defer harness.deinit();

    // The refusal is the embedder's, but the abort is ours: a chain the
    // embedder rejected must never reach `connected`.
    try testing.expectError(error.BadCertificate, harness.connect(&buffers));
    try testing.expectEqual(@as(u8, 1), spy.calls);
    try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
    try testing.expect(!harness.client.peer.verified);
}

test "ALPN: the client reports which of its offers the server took" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    // `h2` first, and the server takes the second — so a client that
    // simply echoed its own preference would fail this.
    try harness.init(.{
        .client_alpn = &.{ "h2", "http/1.1" },
        .server_alpn = "http/1.1",
    });
    defer harness.deinit();
    try harness.connect(&buffers);

    try testing.expectEqualSlices(u8, "http/1.1", harness.client.alpnSelected().?);
}

test "ALPN: a protocol the client never offered is refused" {
    // Our own server will not commit this — it selects only from what
    // the hello advertised — so the violation has to be forged under the
    // genuine handshake keys. RFC 7301 §3.2 makes it the client's job to
    // catch, and a client that trusted the selection would hand the
    // embedder a protocol it never agreed to speak.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .client_alpn = &.{"h2"}, .server_alpn = "h2" });
    defer harness.deinit();

    const hello = harness.client.start(&buffers.client_out);
    const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
    const server_hello_record = recordAt(flight.send, 0);
    _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);
    try testing.expectEqual(ClientHandshake.State.awaiting_encrypted_extensions, harness.client.state);

    var forger = try serverFlightProtector(
        &client_x25519_private,
        hello,
        server_hello_record,
    );
    defer forger.deinit();
    var plaintext: [4096]u8 = undefined;
    // "http/1.1" was never in the offer — only "h2" was.
    const extensions = server_messages.encryptedExtensions(&plaintext, "http/1.1", false);
    var forged_record: [record.wire_record_bytes_max]u8 = undefined;
    const sealed = try forger.seal(.handshake, extensions, &forged_record);

    try testing.expectError(
        error.BadAlpn,
        harness.client.handleRecord(sealed, &buffers.scratch),
    );
    try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
    try testing.expectEqual(@as(?[]const u8, null), harness.client.alpnSelected());
}

test "ALPN: a server that selects nothing leaves the choice unmade" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .client_alpn = &.{ "h2", "http/1.1" }, .server_alpn = null });
    defer harness.deinit();
    try harness.connect(&buffers);

    // Not an error: the embedder decides whether it can proceed without
    // one, which is what a load generator meeting an HTTP/1.1-only
    // server needs to be able to report rather than crash on.
    try testing.expectEqual(@as(?[]const u8, null), harness.client.alpnSelected());
}

test "insecure_no_verification completes against a server that sends a certificate" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .certificate_policy = .insecure_no_verification });
    defer harness.deinit();

    // Regression: the flight-ordering check keyed off the captured leaf
    // key, which this policy never captures — so every such handshake
    // died on `UnexpectedMessage` at the server's CertificateVerify.
    try harness.connect(&buffers);
    try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);
    try testing.expect(!harness.client.peer.verified);
}

test "sendAlert: encrypted once keys exist, plaintext before, and the peer reads both" {
    var buffers: Buffers = .{};

    // Before any ServerHello there is no ladder, so §5.1 plaintext is
    // the only thing the peer could open — and the server, still waiting
    // on a ClientHello, must read it as the fatal alert it is.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        const bare = harness.client.sendAlert(.internal_error, &buffers.client_out);
        try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
        try testing.expectEqual(record.ContentType.alert, try contentTypeOf(bare));
        try testing.expectError(
            error.PeerAlert,
            harness.server.handleRecord(bare, &buffers.server_out),
        );
    }

    // Once the session keys exist the alert travels as application_data
    // on the wire, which is the shape §5 requires and the only one the
    // peer's record layer will open.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        const sealed = harness.client.sendAlert(.illegal_parameter, &buffers.client_out);
        try testing.expect(sealed.len <= ClientHandshake.alert_bytes_min);
        try testing.expectEqual(record.ContentType.application_data, try contentTypeOf(sealed));
        try testing.expectError(
            error.PeerAlert,
            harness.server.handleRecord(sealed, &buffers.server_out),
        );
    }

    // close_notify is the one description that closes rather than fails,
    // and the server half sends it the same way.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        const sealed = harness.server.sendAlert(.close_notify, &buffers.server_out);
        // Our write side only (§6.1): the client has not closed back.
        try testing.expectEqual(ServerHandshake.State.close_sent, harness.server.state);
        const event = (try harness.client.handleRecord(sealed, &buffers.scratch)).?;
        try testing.expectEqual(std.meta.activeTag(event), .closed);
    }
}

test "sendAlert mid-handshake leads with D.4's dummy ChangeCipherSpec" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();

    // Drive only as far as the ServerHello: handshake keys exist, our own
    // Finished flight — and with it the compatibility record — has not
    // gone out. A peer in compatibility mode is still waiting for it, and
    // will not read a protected record that arrives first.
    const hello = harness.client.start(&buffers.client_out);
    const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
    const server_hello = recordAt(flight.send, 0);
    _ = try harness.client.handleRecord(server_hello, &buffers.scratch);
    try testing.expectEqual(ClientHandshake.State.awaiting_encrypted_extensions, harness.client.state);

    const bytes = harness.client.sendAlert(.illegal_parameter, &buffers.client_out);
    const leading = recordAt(bytes, 0);
    try testing.expectEqual(record.ContentType.change_cipher_spec, try contentTypeOf(leading));
    const sealed = recordAt(bytes, leading.len);
    try testing.expectEqual(record.ContentType.application_data, try contentTypeOf(sealed));
    try testing.expectEqual(bytes.len, leading.len + sealed.len);
    try testing.expectError(
        error.PeerAlert,
        harness.server.handleRecord(sealed, &buffers.server_out),
    );
}

fn contentTypeOf(wire_record: []const u8) !record.ContentType {
    const header = try record.parseHeader(wire_record[0..record.header_bytes]);
    return header.content_type;
}

test "an RSA leaf signs the server's CertificateVerify and our client accepts it" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .leaf = .rsa_2048 });
    defer harness.deinit();

    // §4.4.3 admits only rsa_pss_rsae_* for an RSA leaf: PKCS#1 v1.5 is
    // what libcrypto would sign with by default and what 1.3 forbids, so
    // the scheme on the wire is the assertion that matters here.
    try testing.expectEqualSlices(
        backend.SignatureScheme,
        &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
        harness.credentials.signer.supported(),
    );
    try harness.connect(&buffers);
    try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);
    // The client verified through `std.crypto`'s RSA-PSS, not libcrypto's
    // — the same no-shared-code split the ECDSA path draws.
    try testing.expect(harness.client.peer.verified);

    const ping = try harness.client.sendApplicationData("rsa", &buffers.client_out);
    const event = (try harness.server.handleRecord(ping, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "rsa", event.application_data);
}

test "a P-384 leaf signs with ecdsa_secp384r1_sha384 and our client accepts it" {
    // DESIGN.md §1 puts ECDSA P-384 in the signing policy, and
    // `backend.SignatureScheme` has carried `ecdsa_secp384r1_sha384`
    // since the beginning — but every fixture in this tree was P-256 or
    // RSA, so no oracle had ever asked the P-384 signer for a signature.
    // A declared capability nothing exercises is a claim, not a feature.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .leaf = .ecdsa_p384 });
    defer harness.deinit();

    // One scheme, not three: an EC key signs under exactly the digest
    // its curve names, where an RSA modulus admits all three. That is
    // the assertion that says the curve reached the policy, rather than
    // the load merely succeeding.
    try testing.expectEqualSlices(
        backend.SignatureScheme,
        &.{.ecdsa_secp384r1_sha384},
        harness.credentials.signer.supported(),
    );

    try harness.connect(&buffers);
    try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);
    // Signed by libcrypto, verified by `std.crypto` — the same
    // no-shared-code split the P-256 and RSA paths draw, and the reason
    // this is worth a fixture rather than a unit test over the signer.
    try testing.expect(harness.client.peer.verified);
    try testing.expectEqual(
        backend.SignatureScheme.ecdsa_secp384r1_sha384,
        harness.server.signature_scheme,
    );

    const ping = try harness.client.sendApplicationData("p384", &buffers.client_out);
    const event = (try harness.server.handleRecord(ping, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "p384", event.application_data);
}

test "the signing policy is a load-time refusal, not a mid-flight surprise" {
    var storage: [Credentials.chain_bytes_max]u8 = undefined;
    const rsa_cert = @embedFile("testdata/rsa2048-cert.pem");
    const rsa_key = @embedFile("testdata/rsa2048-key.pem");

    // Deterministic nonces and PSS cannot both be had: the salt is fresh
    // per signature by §4.4.3's own rule. An embedder that asked for
    // replayable flights is told so rather than quietly given random ones.
    try testing.expectError(
        error.DeterministicNonceUnsupported,
        Credentials.load(rsa_cert, rsa_key, &storage, true),
    );

    // A modulus below `rsa_bits_min` never reaches the state machine: a
    // 1024-bit key is refused at load, where the operator can read it,
    // rather than mid-flight with a client already waiting.
    try testing.expectError(
        error.UnsupportedKey,
        Credentials.load(rsa_cert, @embedFile("testdata/rsa1024-key.pem"), &storage, false),
    );
}

test "a protected record that is nothing but its content type is refused, not asserted" {
    // §5.4: only application_data may carry a zero-length
    // TLSInnerPlaintext.content. A peer that seals an empty alert or an
    // empty handshake message is sending unexpected_message — and it
    // once reached `assert(payload.len >= 1)` instead, which is a remote
    // abort in any build that keeps assertions on. tlsfuzzer's
    // `test-tls13-empty-alert` is what found it.
    //
    // The forgery is sealed with each machine's genuine session key, so
    // it arrives at the right sequence number and gets all the way to
    // the inner content-type switch, which is the code under test.
    for ([_]record.ContentType{ .alert, .handshake }) |inner| {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);

        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                const empty = try arm.session.?.send.seal(inner, &.{}, &buffers.client_out);
                try testing.expectError(
                    error.UnexpectedMessage,
                    harness.server.handleRecord(empty, &buffers.server_out),
                );
            },
        }
        switch (harness.server.ladder.?) {
            inline else => |*arm| {
                const empty = try arm.session.?.send.seal(inner, &.{}, &buffers.server_out);
                try testing.expectError(
                    error.UnexpectedMessage,
                    harness.client.handleRecord(empty, &buffers.scratch),
                );
            },
        }
    }

    // Mid-handshake too, which is a different arm of the same switch:
    // the client here holds handshake keys and has not seen the server's
    // flight, so the record is opened by `arm.recv` rather than the
    // session. tlsfuzzer reaches this state and the `.connected` one by
    // separate conversations, and so should this.
    {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        const hello = harness.client.start(&buffers.client_out);
        const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);
        try testing.expectEqual(ClientHandshake.State.awaiting_encrypted_extensions, harness.client.state);

        var forger = try serverFlightProtector(
            &client_x25519_private,
            hello,
            server_hello_record,
        );
        defer forger.deinit();
        var forged: [record.wire_record_bytes_max]u8 = undefined;
        const empty = try forger.seal(.alert, &.{}, &forged);
        try testing.expectError(
            error.UnexpectedMessage,
            harness.client.handleRecord(empty, &buffers.scratch),
        );
        try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
    }

    // The same record with one byte of content is ordinary traffic, so
    // the guard above cannot be a blanket refusal of short records.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);
    switch (harness.client.ladder.?) {
        inline else => |*arm| {
            const one = try arm.session.?.send.seal(.application_data, "x", &buffers.client_out);
            const event = (try harness.server.handleRecord(one, &buffers.server_out)).?;
            try testing.expectEqualSlices(u8, "x", event.application_data);
        },
    }
}

test "an alert the server sends before the client's Finished is readable by the client" {
    // §4.4.4: the server's write keys become application keys the moment
    // its Finished goes out — that is what makes 0.5-RTT data legal — and
    // the client installs its application *read* keys as soon as it has
    // verified that Finished. So the window between the server's Finished
    // and the client's is served by application keys in both directions.
    //
    // A server that keeps sealing with its handshake protector through
    // that window sends alerts its peer cannot open. That matters most
    // for the one alert this state exists to send: the refusal of a
    // client Finished that does not verify.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();

    // Drive the handshake until the client is connected, but never hand
    // the client's Finished to the server: that is the window.
    const hello = harness.client.start(&buffers.client_out);
    const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
    var index: usize = 0;
    var count: u8 = 0;
    while (index < flight.send.len) : (count += 1) {
        try testing.expect(count < 8);
        const one = recordAt(flight.send, index);
        _ = try harness.client.handleRecord(one, &buffers.scratch);
        index += one.len;
    }
    try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);
    try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);

    const sealed = harness.server.sendAlert(.decrypt_error, &buffers.server_out);
    try testing.expect(sealed.len >= 1);
    try testing.expectError(
        error.PeerAlert,
        harness.client.handleRecord(sealed, &buffers.scratch),
    );
}

/// An EncryptedExtensions message carrying one extension of our choosing,
/// which `server_messages.encryptedExtensions` deliberately cannot build:
/// it only ever emits a legal ALPN selection, and these tests need the
/// illegal shapes a hostile server would send.
fn forgedEncryptedExtensions(out: []u8, extension_type: u16, data: []const u8) []const u8 {
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .encrypted_extensions);
    const extensions = builder.markU16();
    builder.putU16(extension_type);
    const body = builder.markU16();
    builder.putSlice(data);
    builder.patchU16(body);
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    return builder.written();
}

test "§4.2: EncryptedExtensions may carry only what we offered, where it is legal" {
    // Every shape below once reached our client and was ignored: the
    // loop looked at ALPN and skipped everything else, so a server could
    // hand us any extension it liked. §4.2 makes that
    // unsupported_extension. BoGo's finding 2 is where it was measured.
    const Shape = struct {
        extension_type: u16,
        data: []const u8,
        alpn: []const []const u8,
        server_name: ?[]const u8,
        expected: anyerror,
        note: []const u8,
    };
    const shapes = [_]Shape{
        // An extension nobody has heard of.
        .{
            .extension_type = 0x7f00,
            .data = &.{},
            .alpn = &.{},
            .server_name = null,
            .expected = error.UnsupportedExtension,
            .note = "unknown",
        },
        // key_share: offered in our ClientHello, but §4.2 puts it in
        // ServerHello. Offered is not the same as legal here.
        .{
            .extension_type = 51,
            .data = &.{ 0x00, 0x1d, 0x00, 0x00 },
            .alpn = &.{},
            .server_name = null,
            .expected = error.UnsupportedExtension,
            .note = "key_share in EE",
        },
        // A well-formed server_name ack we never asked for.
        .{
            .extension_type = 0,
            .data = &.{},
            .alpn = &.{},
            .server_name = null,
            .expected = error.UnsupportedExtension,
            .note = "unsolicited SNI ack",
        },
        // The same ack, asked for, but with bytes after it: a body we
        // cannot read is decode_error, not unsupported_extension.
        .{
            .extension_type = 0,
            .data = &.{0x00},
            .alpn = &.{},
            .server_name = "example.com",
            .expected = error.MalformedExtension,
            .note = "SNI ack with trailing data",
        },
        // Malformed *and* unsolicited, which is the only combination
        // where the order of the two checks is observable — the two
        // shapes above each satisfy one condition and would pass with the
        // checks either way round. Parsing wins: decode_error.
        .{
            .extension_type = 0,
            .data = &.{0x00},
            .alpn = &.{},
            .server_name = null,
            .expected = error.MalformedExtension,
            .note = "SNI ack malformed and unsolicited",
        },
        // The same combination for ALPN: a list whose framing does not
        // parse, sent when we offered no ALPN at all. `selectAlpn` reads
        // the body before it asks whether we offered the extension, so
        // this is the framing error rather than unsupported_extension.
        .{
            .extension_type = 16,
            .data = &.{ 0x00, 0x05, 0x04, 'a' },
            .alpn = &.{},
            .server_name = null,
            .expected = error.BadAlpn,
            .note = "ALPN malformed and unoffered",
        },
        // ALPN selected when we offered none: the extension itself is
        // unsolicited, rather than a bad choice within one we sent.
        .{
            .extension_type = 16,
            .data = &.{ 0x00, 0x05, 0x04, 'a', 'l', 'p', 'n' },
            .alpn = &.{},
            .server_name = null,
            .expected = error.UnsupportedExtension,
            .note = "ALPN never offered",
        },
    };
    for (shapes) |shape| {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{ .client_alpn = shape.alpn, .server_alpn = null });
        defer harness.deinit();
        harness.client.config.server_name = shape.server_name;

        const hello = harness.client.start(&buffers.client_out);
        const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);

        var forger = try serverFlightProtector(
            &client_x25519_private,
            hello,
            server_hello_record,
        );
        defer forger.deinit();
        var plaintext: [4096]u8 = undefined;
        const message = forgedEncryptedExtensions(&plaintext, shape.extension_type, shape.data);
        var forged_record: [record.wire_record_bytes_max]u8 = undefined;
        const sealed = try forger.seal(.handshake, message, &forged_record);
        _ = harness.client.handleRecord(sealed, &buffers.scratch) catch |err| {
            if (err != shape.expected) {
                std.debug.print("shape '{s}': expected {t}, got {t}\n", .{ shape.note, shape.expected, err });
                return error.TestUnexpectedResult;
            }
            continue;
        };
        std.debug.print("shape '{s}': accepted, expected {t}\n", .{ shape.note, shape.expected });
        return error.TestUnexpectedResult;
    }
}

test "an empty application_data record is refused, not asserted away" {
    // §5.1 permits a zero-length fragment for application_data and for
    // nothing else, so `record.parseHeader` admits it by design — and
    // `handleProtectedRecord` then asserted the record was longer than
    // its own header. Five bytes from a connected peer aborted the
    // server. TLS-Anvil found it 51 tests into its first run.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);

    var empty: [record.header_bytes]u8 = undefined;
    record.writeHeader(
        .{ .content_type = .application_data, .length = 0 },
        empty[0..record.header_bytes],
    );
    // The header parses — that is the point — and the refusal comes from
    // the record layer, which knows a protected record needs a tag.
    try testing.expectError(
        error.BadInnerPlaintext,
        harness.server.handleRecord(&empty, &buffers.server_out),
    );
}

test "§5: a ChangeCipherSpec outside its window is unexpected_message" {
    // "An implementation may receive an unencrypted record of type
    // change_cipher_spec ... at any time after the first ClientHello
    // message has been sent or received and before the peer's Finished
    // message has been received and MUST simply drop it ... If an
    // implementation detects a change_cipher_spec record received before
    // the first ClientHello message or after the peer's Finished
    // message, it MUST be treated as an unexpected record type."
    //
    // zssl dropped it wherever it landed. TLS-Anvil's
    // `sendLegacyChangeCipherSpecAfterFinished` is the case, and it only
    // became visible once the harness stopped closing the connection on
    // a deadline before the corpus could tell.
    var buffers: Buffers = .{};
    var ccs: [record.header_bytes + 1]u8 = undefined;
    record.writeHeader(
        .{ .content_type = .change_cipher_spec, .length = 1 },
        ccs[0..record.header_bytes],
    );
    ccs[record.header_bytes] = 0x01;

    // After the peer's Finished, on both machines.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        try testing.expectError(
            error.UnexpectedMessage,
            harness.server.handleRecord(&ccs, &buffers.server_out),
        );
    }
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        try testing.expectError(
            error.UnexpectedMessage,
            harness.client.handleRecord(&ccs, &buffers.scratch),
        );
    }

    // And after a close_notify that itself arrived post-Finished: the
    // machine is `closed` rather than `connected`, may still be fed, and
    // is unambiguously past the peer's Finished. The first version of
    // this fix checked only `connected` and let this through.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        const bye = harness.client.sendAlert(.close_notify, &buffers.client_out);
        const event = (try harness.server.handleRecord(bye, &buffers.server_out)).?;
        try testing.expectEqual(std.meta.activeTag(event), .closed);
        // The read side, and the §5 window is shut either way — a
        // half-closed connection is well past the peer's Finished.
        try testing.expectEqual(ServerHandshake.State.close_received, harness.server.state);
        try testing.expectError(
            error.UnexpectedMessage,
            harness.server.handleRecord(&ccs, &buffers.server_out),
        );
    }

    // Before the first ClientHello, which the server can tell apart.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try testing.expectError(
            error.UnexpectedMessage,
            harness.server.handleRecord(&ccs, &buffers.server_out),
        );
    }

    // Inside the window it is still dropped — D.4's compatibility record
    // is the reason this is tolerated at all, and breaking that would
    // trade one interop failure for another.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        const hello = harness.client.start(&buffers.client_out);
        _ = try harness.server.handleRecord(hello, &buffers.server_out);
        try testing.expect(try harness.server.handleRecord(&ccs, &buffers.server_out) == null);
    }
}

test "§5: a ChangeCipherSpec carrying anything but 0x01 is unexpected_message" {
    // "An implementation which receives any other change_cipher_spec
    // value ... MUST abort the handshake with an "unexpected_message"
    // alert." zssl bounded how many of these it would take and where,
    // and never read the byte — so `01 01` was accepted as compatibility
    // filler, which is tlsfuzzer's `two byte long CCS` and its
    // `multiple CCS Messages in one TLS record` (docs/TLSFUZZER.md
    // finding 8).
    //
    // Every case here sits *inside* §5's window, where the record would
    // otherwise be dropped and the handshake would continue: that is
    // what makes this about the payload and not about the position.
    const payloads = [_][]const u8{
        // The value that is not 0x01. TLS 1.2's message body was this
        // same byte, so there has never been another legal one.
        &.{0x00},
        &.{0x02},
        &.{0xff},
        // More than one byte of it, which is "any other value" too —
        // the record's whole content is the message.
        &.{ 0x01, 0x01 },
        &.{ 0x01, 0x00 },
        &([_]u8{0x01} ** 64),
    };

    for (payloads) |payload| {
        var buffers: Buffers = .{};
        var storage: [record.header_bytes + 64]u8 = undefined;
        record.writeHeader(
            .{ .content_type = .change_cipher_spec, .length = @intCast(payload.len) },
            storage[0..record.header_bytes],
        );
        @memcpy(storage[record.header_bytes..][0..payload.len], payload);
        const ccs_record = storage[0 .. record.header_bytes + payload.len];

        // Server: after the ClientHello, which is squarely inside the
        // window — the one-byte version of this record is dropped here
        // and the handshake carries on.
        {
            var harness: Harness = undefined;
            try harness.init(.{});
            defer harness.deinit();
            const hello = harness.client.start(&buffers.client_out);
            _ = try harness.server.handleRecord(hello, &buffers.server_out);
            try testing.expectError(
                error.UnexpectedMessage,
                harness.server.handleRecord(ccs_record, &buffers.server_out),
            );
        }

        // Client: after its own ClientHello has gone out, which is the
        // same window seen from the other side.
        {
            var harness: Harness = undefined;
            try harness.init(.{});
            defer harness.deinit();
            _ = harness.client.start(&buffers.client_out);
            try testing.expectError(
                error.UnexpectedMessage,
                harness.client.handleRecord(ccs_record, &buffers.scratch),
            );
        }
    }
}

test "§6.1: user_canceled is ignored and bounded, other warnings are refused" {
    // The three dispositions a peer can reach, driven through a real
    // connection rather than through `alert.disposition` alone. Every
    // alert here is sealed with the client's genuine session key, so it
    // arrives at the right sequence number and reaches the handler.
    const user_canceled = [_]u8{ 1, 90 };

    // Four warning-level user_canceled alerts are ignored — the JDK 11
    // behaviour §6.1 leaves legal — and the fifth is not, because
    // ignoring is still work a peer is buying.
    {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                for (0..flood.warning_alerts_max) |_| {
                    const sealed = try arm.session.?.send.seal(.alert, &user_canceled, &buffers.client_out);
                    try testing.expect(try harness.server.handleRecord(sealed, &buffers.server_out) == null);
                    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
                }
                const one_too_many = try arm.session.?.send.seal(.alert, &user_canceled, &buffers.client_out);
                try testing.expectError(
                    error.TooManyWarningAlerts,
                    harness.server.handleRecord(one_too_many, &buffers.server_out),
                );
            },
        }
    }

    // Application bytes are progress, so the budget comes back. Without
    // this a long-lived connection would eventually die of alerts it was
    // told to ignore.
    {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                for (0..flood.warning_alerts_max) |_| {
                    const sealed = try arm.session.?.send.seal(.alert, &user_canceled, &buffers.client_out);
                    _ = try harness.server.handleRecord(sealed, &buffers.server_out);
                }
                const data = try arm.session.?.send.seal(.application_data, "hello", &buffers.client_out);
                const event = (try harness.server.handleRecord(data, &buffers.server_out)).?;
                try testing.expectEqualStrings("hello", event.application_data);
                // The whole budget again, on the far side of one byte.
                for (0..flood.warning_alerts_max) |_| {
                    const sealed = try arm.session.?.send.seal(.alert, &user_canceled, &buffers.client_out);
                    _ = try harness.server.handleRecord(sealed, &buffers.server_out);
                }
            },
        }
    }

    // A warning level TLS 1.3 gives no meaning to. `alert.encode` cannot
    // produce one — it makes everything but close_notify and
    // user_canceled fatal — so this is what a *peer* can send us and we
    // cannot send back.
    {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                const warned = try arm.session.?.send.seal(.alert, &.{ 1, 40 }, &buffers.client_out);
                try testing.expectError(
                    error.BadAlert,
                    harness.server.handleRecord(warned, &buffers.server_out),
                );
            },
        }
    }

    // The ordering that carries the security of this: user_canceled is
    // tolerated because it is a *warning*. At fatal level the peer is
    // aborting, and reading it as "ignore" would discard that.
    {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                const fatal = try arm.session.?.send.seal(.alert, &.{ 2, 90 }, &buffers.client_out);
                try testing.expectError(
                    error.PeerAlert,
                    harness.server.handleRecord(fatal, &buffers.server_out),
                );
            },
        }
    }
}

test "§6.1: a close closes one direction, and the peer may answer" {
    // Finding 6. A single `.closed` state could not say *which*
    // direction had closed, so it said both: after the peer's
    // close_notify an embedder could not answer with one of its own
    // (`sendClose` asserted `.connected`, so answering was an abort),
    // and after its own it could not read on to find out whether the
    // peer had closed cleanly or the stream had simply been cut.
    var buffers: Buffers = .{};

    // Server closes first. Its write side shuts; its read side does not.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);

        const bye = try harness.server.sendClose(&buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.close_sent, harness.server.state);
        try testing.expect(!harness.server.writable());
        try testing.expect(harness.server.readable());

        // The client reads it, and its own halves move the other way.
        const seen = (try harness.client.handleRecord(bye, &buffers.scratch)).?;
        try testing.expectEqual(std.meta.activeTag(seen), .closed);
        try testing.expectEqual(ClientHandshake.State.close_received, harness.client.state);
        try testing.expect(harness.client.writable());
        try testing.expect(!harness.client.readable());

        // Answering is the ordinary thing to do from here, and is what
        // used to abort. Both machines end fully closed.
        const answer = try harness.client.sendClose(&buffers.client_out);
        try testing.expectEqual(ClientHandshake.State.closed, harness.client.state);
        const done = (try harness.server.handleRecord(answer, &buffers.server_out)).?;
        try testing.expectEqual(std.meta.activeTag(done), .closed);
        try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
        try testing.expect(!harness.server.readable());
        try testing.expect(!harness.server.writable());
    }

    // The half-close is what lets an orderly shutdown be told from a
    // truncated one: after our close_notify the peer's records still
    // arrive, so an alert instead of a close is legible rather than
    // silence. `Unclean-Shutdown-Alert` is the case.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        _ = try harness.server.sendClose(&buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.close_sent, harness.server.state);
        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                const angry = try arm.session.?.send.seal(.alert, &.{ 2, 30 }, &buffers.client_out);
                try testing.expectError(
                    error.PeerAlert,
                    harness.server.handleRecord(angry, &buffers.server_out),
                );
            },
        }
    }

    // Application data still flows the open way. The peer closed its
    // write side; ours is untouched, which is the whole point of §6.1
    // being two directions rather than one switch.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        const bye = try harness.client.sendClose(&buffers.client_out);
        _ = try harness.server.handleRecord(bye, &buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.close_received, harness.server.state);
        const late = try harness.server.sendApplicationData("still here", &buffers.server_out);
        const event = (try harness.client.handleRecord(late, &buffers.scratch)).?;
        try testing.expectEqualStrings("still here", event.application_data);
    }

    // And a record arriving after the peer's close_notify is refused:
    // our read side is shut, whatever our write side is doing.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try harness.connect(&buffers);
        switch (harness.client.ladder.?) {
            inline else => |*arm| {
                const bye = try harness.client.sendClose(&buffers.client_out);
                _ = try harness.server.handleRecord(bye, &buffers.server_out);
                const late = try arm.session.?.send.seal(.application_data, "too late", &buffers.client_out);
                try testing.expectError(
                    error.UnexpectedMessage,
                    harness.server.handleRecord(late, &buffers.server_out),
                );
            },
        }
    }
}

test "§6.1: a close before there is a connection closes the machine, not half of it" {
    // The half-close model has a precondition its two predicates do not
    // state: `writable()` and `readable()` are read as "the keys for
    // that direction exist", because every write entry point unwraps
    // `ladder.?` behind one. Half-closing before the session keys exist
    // makes them lie, and the embedder doing the ordinary next thing —
    // answering a close with a close — then aborts the process on one
    // record of peer input. The review caught this; these pin it.
    var buffers: Buffers = .{};

    // A plaintext close_notify as the very first record on the wire,
    // before any ClientHello. There is no ladder to half-close.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        const bye = [_]u8{ 21, 3, 3, 0, 2, 1, 0 };
        const event = (try harness.server.handleRecord(&bye, &buffers.server_out)).?;
        try testing.expectEqual(std.meta.activeTag(event), .closed);
        try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
        try testing.expect(harness.server.ladder == null);
        // Both false, so `sendClose`'s `ladder.?` is unreachable.
        try testing.expect(!harness.server.writable());
        try testing.expect(!harness.server.readable());
    }

    // Our own close_notify before the handshake, which `sendAlert`
    // documents as callable in every state. It must not open a read
    // side there is no key for.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        _ = harness.server.sendAlert(.close_notify, &buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
        try testing.expect(!harness.server.readable());
        // A protected record now is refused rather than opened against
        // a session that does not exist.
        const protected = [_]u8{ 23, 3, 3, 0, 1, 0 };
        try testing.expectError(
            error.UnexpectedMessage,
            harness.server.handleRecord(&protected, &buffers.server_out),
        );
    }

    // Mid-handshake: the ladder exists but the session keys do not.
    // This is the narrower version of the same trap.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        const hello = harness.client.start(&buffers.client_out);
        _ = try harness.server.handleRecord(hello, &buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);
        _ = harness.server.sendAlert(.close_notify, &buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
        try testing.expect(!harness.server.readable());
        try testing.expect(!harness.server.writable());
    }

    // And a failed machine stays unusable: a close_notify must not
    // revive it into a state that admits records again.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        _ = harness.server.sendAlert(.internal_error, &buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
        _ = harness.server.sendAlert(.close_notify, &buffers.server_out);
        try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
        try testing.expect(!harness.server.readable());
        try testing.expect(!harness.server.writable());
    }

    // The client half of the first case, since both roles unwrap the
    // same optional behind the same predicate.
    {
        var harness: Harness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        _ = harness.client.start(&buffers.client_out);
        const bye = [_]u8{ 21, 3, 3, 0, 2, 1, 0 };
        const event = (try harness.client.handleRecord(&bye, &buffers.scratch)).?;
        try testing.expectEqual(std.meta.activeTag(event), .closed);
        try testing.expectEqual(ClientHandshake.State.closed, harness.client.state);
        try testing.expect(!harness.client.writable());
        try testing.expect(!harness.client.readable());
    }
}

test "§5.1: a record packing three post-handshake messages yields all three" {
    // Finding 1's second half, and the case that broke it. `drain` must
    // decide "nothing more" from the *assembler*, never from what the
    // last message resolved to: a KeyUpdate carrying
    // update_not_requested is consumed and produces no event, and
    // reading that as "the record is done" strands whatever was packed
    // behind it. The peer chooses the order, so the strand is reachable
    // from the wire — and the next `handleRecord` would then answer
    // `EventsPending`, blaming an embedder that did everything right.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);

    // ticket, KeyUpdate(update_not_requested), ticket — in one record.
    var plaintext: [256]u8 = undefined;
    var b = wire.Builder.init(&plaintext);
    for (0..2) |round| {
        const ticket = handshake.beginMessage(&b, .new_session_ticket);
        b.putU32(7200); // lifetime
        b.putU32(0); // age_add
        b.putByte(1); // ticket_nonce<1>
        b.putByte(@intCast(round));
        b.putU16(1); // ticket<1>
        b.putByte(0xa0 + @as(u8, @intCast(round)));
        b.putU16(0); // no extensions
        handshake.endMessage(&b, ticket);
        if (round == 0) {
            const update = handshake.beginMessage(&b, .key_update);
            b.putByte(0); // update_not_requested: consumed, no reply
            handshake.endMessage(&b, update);
        }
    }

    var seen: [2]u8 = undefined;
    var tickets: usize = 0;
    switch (harness.server.ladder.?) {
        inline else => |*arm| {
            const sealed = try arm.session.?.send.seal(.handshake, b.written(), &buffers.server_out);
            // §4.6.3: the sender emits under the current generation and
            // rotates after. Forging the message without this would
            // leave the client's receive side a generation ahead of the
            // server's send side, and the follow-up record below would
            // fail to open for a reason that is the test's fault.
            try arm.session.?.rotateTransmit();
            var event = try harness.client.handleRecord(sealed, &buffers.scratch);
            while (event) |ready| : (event = try harness.client.drain(&buffers.scratch)) {
                if (std.meta.activeTag(ready) == .ticket) {
                    seen[tickets] = ready.ticket.ticket[0];
                    tickets += 1;
                }
            }
        },
    }

    // Both tickets, not just the one ahead of the KeyUpdate.
    try testing.expectEqual(@as(usize, 2), tickets);
    try testing.expectEqualSlices(u8, &.{ 0xa0, 0xa1 }, &seen);

    // And nothing is left behind: a following record is accepted rather
    // than refused as `EventsPending`.
    switch (harness.server.ladder.?) {
        inline else => |*arm| {
            const data = try arm.session.?.sealApplicationData("after", &buffers.server_out);
            const event = (try harness.client.handleRecord(data, &buffers.scratch)).?;
            try testing.expectEqualStrings("after", event.application_data);
        },
    }
}

test "§6: a fatal alert from the peer says which alert it was" {
    // `PeerAlert` is one error for every refusal a peer can send, and a
    // Zig error carries no payload — so an embedder that logs or
    // re-maps the peer's alert had nothing to read. BoGo's ErrorMap was
    // the same problem from outside: a case expecting record_overflow
    // was satisfied by any fatal alert at all, and one of them had been
    // passing on that (docs/BOGO.md finding 17).
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);
    try testing.expectEqual(@as(?u8, null), harness.server.peer_alert_description);

    // A fatal alert the client would never send, so the byte read back
    // can only have come from this record.
    switch (harness.client.ladder.?) {
        inline else => |*arm| {
            const sealed = try arm.session.?.send.seal(
                .alert,
                &alert.encode(.record_overflow),
                &buffers.client_out,
            );
            try testing.expectError(
                error.PeerAlert,
                harness.server.handleRecord(sealed, &buffers.server_out),
            );
        },
    }
    try testing.expectEqual(
        @as(?u8, @intFromEnum(alert.Description.record_overflow)),
        harness.server.peer_alert_description,
    );
}

test "§6: an alert description this library does not name survives as its byte" {
    // §6 lets a peer send any byte, and `alert.Description` names only
    // the ones zssl uses. Reporting the wire value rather than the enum
    // is what keeps `decompression_failure` — a TLS 1.2-era alert with
    // no place in this library — readable by an embedder that meets one.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);

    const decompression_failure: u8 = 30;
    try testing.expectEqual(
        @as(?alert.Description, null),
        std.enums.fromInt(alert.Description, decompression_failure),
    );
    switch (harness.client.ladder.?) {
        inline else => |*arm| {
            const sealed = try arm.session.?.send.seal(
                .alert,
                &.{ 2, decompression_failure },
                &buffers.client_out,
            );
            try testing.expectError(
                error.PeerAlert,
                harness.server.handleRecord(sealed, &buffers.server_out),
            );
        },
    }
    try testing.expectEqual(@as(?u8, decompression_failure), harness.server.peer_alert_description);
}

test "§2: 0.5-RTT data, and the nonce sequence that survives the handoff" {
    // The server may answer after its own Finished and before the
    // client's. `finishFlight` already moved the send side onto
    // application keys, so these records are protected exactly as
    // post-handshake ones are — same key, one continuous sequence.
    //
    // That continuity is the whole hazard. The session's send protector
    // is built from the same secret, so a count that restarted would
    // reuse a nonce under a key that had already seen it. There was an
    // assertion demanding `sequence == 0` at the handoff precisely
    // because nothing wrote in this window before; this walks the case
    // that assertion was guarding against.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();

    const hello = harness.client.start(&buffers.client_out);
    const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    try testing.expect(harness.server.halfRttWritable());
    try testing.expect(!harness.server.writable());

    // Two records written before the client has said anything at all.
    var flight_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
    @memcpy(flight_storage[0..flight.send.len], flight.send);
    const flight_bytes = flight_storage[0..flight.send.len];
    var half_rtt: [2 * record.wire_record_bytes_max]u8 = undefined;
    var half_rtt_bytes: usize = 0;
    for ([_][]const u8{ "half-rtt one", "half-rtt two" }) |payload| {
        const sealed = try harness.server.sendApplicationData(payload, &buffers.server_out);
        @memcpy(half_rtt[half_rtt_bytes..][0..sealed.len], sealed);
        half_rtt_bytes += sealed.len;
    }

    // Now finish the handshake. The session inherits the sequence.
    var reply_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
    var reply_bytes: usize = 0;
    var index: usize = 0;
    var count: u8 = 0;
    while (index < flight_bytes.len) : (count += 1) {
        try testing.expect(count < 8);
        const one = recordAt(flight_bytes, index);
        if (try harness.client.handleRecord(one, &buffers.scratch)) |event| switch (event) {
            .connected => |bytes| {
                @memcpy(reply_storage[0..bytes.len], bytes);
                reply_bytes = bytes.len;
            },
            else => return error.TestUnexpectedResult,
        };
        index += one.len;
    }
    const reply = reply_storage[0..reply_bytes];
    var final: ?ServerHandshake.Event = null;
    index = 0;
    count = 0;
    while (index < reply.len) : (count += 1) {
        try testing.expect(count < 8);
        const one = recordAt(reply, index);
        if (try harness.server.handleRecord(one, &buffers.server_out)) |event| final = event;
        index += one.len;
    }
    try testing.expectEqual(std.meta.activeTag(final.?), .connected);
    // Two records went out early, so the session starts at two.
    const transmit = harness.server.exportKeyMaterial(.transmit);
    try testing.expectEqual(@as(u64, 2), transmit.next_sequence);

    // And the client reads all three in order, which it can only do if
    // every nonce was distinct and consecutive.
    index = 0;
    var seen: usize = 0;
    const expected = [_][]const u8{ "half-rtt one", "half-rtt two", "after" };
    const after = try harness.server.sendApplicationData("after", &buffers.server_out);
    @memcpy(half_rtt[half_rtt_bytes..][0..after.len], after);
    half_rtt_bytes += after.len;
    while (index < half_rtt_bytes) : (seen += 1) {
        try testing.expect(seen < expected.len);
        const one = recordAt(half_rtt[0..half_rtt_bytes], index);
        const event = (try harness.client.handleRecord(one, &buffers.scratch)).?;
        try testing.expectEqualSlices(u8, expected[seen], event.application_data);
        index += one.len;
    }
    try testing.expectEqual(expected.len, seen);
}

test "§4.6.1: a ticket's early_data limit is read, and its grammar held to" {
    // The extension is empty in a ClientHello and a u32 here — one code
    // point, two shapes — so the body has to be read rather than
    // skipped. A block we ignore is still a block we parse, which is
    // docs/BOGO.md finding 7's rule; this is that rule applied to a
    // field we now act on.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    try harness.connect(&buffers);

    // A ticket with no early_data extension at all: null, not zero.
    // "Advertised nothing" and "advertised a limit of zero" are
    // different statements and a client must not confuse them.
    const plain = try harness.server.sendNewSessionTicket(&.{
        .lifetime_s = 7200,
        .age_add = 1,
        .ticket_nonce = &.{0x11},
        .ticket = "no-early-data",
    }, &buffers.server_out);
    const plain_event = (try harness.client.handleRecord(plain, &buffers.scratch)).?;
    try testing.expectEqual(@as(?u32, null), plain_event.ticket.early_data_bytes_max);

    // Zero is a real answer and reaches the embedder as one.
    const zero = try harness.server.sendNewSessionTicket(&.{
        .lifetime_s = 7200,
        .age_add = 1,
        .ticket_nonce = &.{0x12},
        .ticket = "zero-early-data",
        .early_data_bytes_max = 0,
    }, &buffers.server_out);
    const zero_event = (try harness.client.handleRecord(zero, &buffers.scratch)).?;
    try testing.expectEqual(@as(?u32, 0), zero_event.ticket.early_data_bytes_max);

    // And a body that is not four bytes is a message that did not
    // decode, whatever it holds.
    var storage: [256]u8 = undefined;
    var builder = wire.Builder.init(&storage);
    const message = handshake.beginMessage(&builder, .new_session_ticket);
    builder.putU32(7200);
    builder.putU32(1);
    builder.putByte(1);
    builder.putByte(0x13);
    builder.putU16(5);
    builder.putSlice("short");
    const extensions = builder.markU16();
    builder.putU16(42); // early_data
    const body = builder.markU16();
    builder.putU16(0xbeef); // two bytes where §4.6.1 writes four
    builder.patchU16(body);
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    switch (harness.server.ladder.?) {
        inline else => |*arm| {
            const malformed = try arm.session.?.send.seal(
                .handshake,
                builder.written(),
                &buffers.server_out,
            );
            try testing.expectError(
                error.Truncated,
                harness.client.handleRecord(malformed, &buffers.scratch),
            );
        },
    }
}

test "§4.4.3: a CertificateVerify scheme we never offered is illegal_parameter" {
    // Two shapes of "not offered", and they used to be indistinguishable
    // from a signature that failed: both returned `BadSignature`, whose
    // alert is decrypt_error. §4.4.3 names illegal_parameter for this,
    // and the difference is not cosmetic — it tells the peer it broke the
    // negotiation rather than that its key is bad, and it tells the
    // embedder no signature was ever checked.
    //
    // Our own server will not commit either, since it signs only with
    // what the hello advertised, so both are forged under the genuine
    // handshake keys.
    const Shape = struct {
        name: []const u8,
        offered: []const backend.SignatureScheme,
        /// The wire code point the forged CertificateVerify carries.
        signed_with: u16,
    };
    for ([_]Shape{
        // A code point outside the five this library implements at all.
        // 0x0807 is ed25519, which §4.4.3 permits and we do not hold.
        .{
            .name = "a scheme the library does not implement",
            .offered = &client_messages.signature_schemes_default,
            .signed_with = 0x0807,
        },
        // A scheme we verify perfectly well, withheld by the embedder.
        // This is the one that proves `verify_schemes` is a promise
        // rather than a hint: nothing about 0x0503 is beyond us, and it
        // is refused because the hello did not offer it.
        .{
            .name = "a scheme the embedder withheld",
            .offered = &.{.ecdsa_secp256r1_sha256},
            .signed_with = 0x0503,
        },
    }) |shape| {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{ .client_verify_schemes = shape.offered });
        defer harness.deinit();

        const hello = harness.client.start(&buffers.client_out);
        const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);

        var forger = try serverFlightProtector(
            &client_x25519_private,
            hello,
            server_hello_record,
        );
        defer forger.deinit();

        // EncryptedExtensions and the server's real Certificate first:
        // the client refuses a CertificateVerify that arrives out of
        // order, and this test is about the scheme, not the ordering.
        var plaintext: [4096]u8 = undefined;
        var forged: [record.wire_record_bytes_max]u8 = undefined;
        const extensions = server_messages.encryptedExtensions(&plaintext, "http/1.1", false);
        _ = try harness.client.handleRecord(try forger.seal(.handshake, extensions, &forged), &buffers.scratch);
        const chain = server_messages.certificateChain(&plaintext, harness.credentials.chain());
        _ = try harness.client.handleRecord(try forger.seal(.handshake, chain, &forged), &buffers.scratch);

        // The signature body is deliberately garbage: the scheme check
        // must fire before anything is verified, and a test that passed
        // only because the bytes were also wrong would prove nothing.
        var body: [128]u8 = undefined;
        const verify = server_messages.certificateVerify(
            &body,
            shape.signed_with,
            &(.{0xa5} ** 64),
        );

        try testing.expectError(
            error.UnofferedSignatureScheme,
            harness.client.handleRecord(
                try forger.seal(.handshake, verify, &forged),
                &buffers.scratch,
            ),
        );
        try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
        // Nothing was verified, and nothing is claimed to have been.
        try testing.expect(!harness.client.peer.verified);
        try testing.expectEqual(
            @as(?backend.SignatureScheme, null),
            harness.client.peer.scheme,
        );
    }
}

test "§4.4.2: the embedder's signing preference is obeyed, and refused when empty" {
    // An RSA modulus signs under all three PSS digests, so it is the one
    // fixture where narrowing has something to choose between: the key
    // could satisfy any of them and the answer has to come from the
    // configured order rather than the signer's own.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{
        .leaf = .rsa_2048,
        // Deliberately *not* the signer's own order, which leads with
        // sha256 — a test that named sha256 would pass without the
        // preference being read at all.
        .server_signing_schemes = &.{ 0x0806, 0x0805, 0x0804 },
    });
    defer harness.deinit();
    try harness.connect(&buffers);
    try testing.expectEqual(
        backend.SignatureScheme.rsa_pss_rsae_sha512,
        harness.server.signature_scheme,
    );
    try testing.expect(harness.client.peer.verified);

    // And the misconfiguration the field documents: a scheme this key
    // cannot produce is answered on the wire, not asserted away. A P-256
    // curve over an RSA key is exactly the kind of pin an embedder gets
    // wrong once, and §4.4.2 leaves it nothing to sign with.
    var pinned: Harness = undefined;
    try pinned.init(.{
        .leaf = .rsa_2048,
        .server_signing_schemes = &.{0x0403},
    });
    defer pinned.deinit();
    var pinned_buffers: Buffers = .{};
    const hello = pinned.client.start(&pinned_buffers.client_out);
    try testing.expectError(
        error.HandshakeFailure,
        pinned.server.handleRecord(hello, &pinned_buffers.server_out),
    );
}

test "§7.5: both machines export the same keying material, and not before" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();

    // Before the handshake there is no exporter_master, and the honest
    // answer is an error. Zeroes would be worse: they look like keying
    // material and an embedder would ship them.
    var early: [32]u8 = undefined;
    try testing.expectError(
        error.HandshakeNotComplete,
        harness.client.exporter("label", "context", &early),
    );
    try testing.expectError(
        error.HandshakeNotComplete,
        harness.server.exporter("label", "context", &early),
    );

    try harness.connect(&buffers);

    // The property RFC 5705 exists for: two ends of one connection,
    // sharing no state but the handshake, agreeing byte for byte — and
    // at a length that needs more than one HKDF block, because the
    // single-block case would pass a truncating implementation.
    var ours: [1024]u8 = undefined;
    var theirs: [1024]u8 = undefined;
    try harness.server.exporter("EXPORTER-Channel-Binding", "context", &ours);
    try harness.client.exporter("EXPORTER-Channel-Binding", "context", &theirs);
    try testing.expectEqualSlices(u8, &ours, &theirs);
    // Not zeroes, which is the failure mode a memcmp of two broken
    // implementations would sail straight past.
    try testing.expect(!std.mem.allEqual(u8, &ours, 0));

    // Every comparison below is against a baseline of the *same length*.
    // §7.1 puts the requested length inside HkdfLabel, so two exports of
    // different sizes differ no matter what else is equal — comparing
    // 1024 bytes against 32 would pass an implementation that ignored
    // the label and the context entirely. It did, when this test first
    // made that mistake.
    // For the same reason, a 1024-byte export's first 32 bytes are *not*
    // a 32-byte export, so the baseline is derived rather than sliced.
    var baseline: [32]u8 = undefined;
    try harness.server.exporter("EXPORTER-Channel-Binding", "context", &baseline);
    try testing.expect(!std.mem.eql(u8, ours[0..32], &baseline));

    // §7.5 hashes the context into the derivation, so a different one is
    // a different secret. An implementation that dropped it would agree
    // with itself while binding nothing.
    var other_context: [32]u8 = undefined;
    try harness.server.exporter("EXPORTER-Channel-Binding", "different", &other_context);
    try testing.expect(!std.mem.eql(u8, &baseline, &other_context));

    // As does a different label.
    var other_label: [32]u8 = undefined;
    try harness.server.exporter("EXPORTER-Other", "context", &other_label);
    try testing.expect(!std.mem.eql(u8, &baseline, &other_label));

    // An empty context is a request §7.5 has a shape for, and is not the
    // same request as any non-empty one.
    var empty_context: [32]u8 = undefined;
    try harness.server.exporter("EXPORTER-Channel-Binding", "", &empty_context);
    try testing.expect(!std.mem.eql(u8, &baseline, &empty_context));

    // An empty *label* too. §7.1's `opaque label<7..255>` cannot encode
    // one — "tls13 " is only six bytes — but HkdfLabel is hashed and
    // never transmitted, and every implementation BoGo drives accepts
    // it. This asserted `label.len >= 1` until BoGo panicked the shim on
    // its own configuration.
    var empty_label: [32]u8 = undefined;
    var empty_label_peer: [32]u8 = undefined;
    try harness.server.exporter("", "context", &empty_label);
    try harness.client.exporter("", "context", &empty_label_peer);
    try testing.expectEqualSlices(u8, &empty_label, &empty_label_peer);
    try testing.expect(!std.mem.eql(u8, &baseline, &empty_label));
}

test "§7.5: a server can export inside the 0.5-RTT window" {
    // The half-RTT case BoGo drives: the server's flight is out, the
    // client's Finished has not arrived, and §7.1 says exporter_master
    // is already derivable because its transcript ends at the *server*
    // Finished. A server answering early data is exactly who asks.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();

    const hello = harness.client.start(&buffers.client_out);
    _ = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
    try testing.expect(harness.server.halfRttWritable());
    try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);

    var half_rtt: [32]u8 = undefined;
    try harness.server.exporter("EXPORTER-Channel-Binding", "context", &half_rtt);
    try testing.expect(!std.mem.allEqual(u8, &half_rtt, 0));
}

test "§4.3.2 end to end: mTLS, with the client's possession actually proven" {
    // Both production machines, mutually authenticated. The claim is not
    // that the handshake completes — an empty certificate under
    // `require = false` completes too — but that the *server* verified a
    // signature the *client* made with a key only it holds.
    var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
    var client_credentials = try Credentials.load(
        @embedFile("testdata/cert.pem"),
        @embedFile("testdata/key.pem"),
        &chain_storage,
        true,
    );
    defer client_credentials.deinit();

    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{
        .client_auth = .{ .require = true },
        .client_credentials = &client_credentials,
    });
    defer harness.deinit();
    try harness.connect(&buffers);

    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
    try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);
    // The whole point: the server holds a verified client certificate.
    try testing.expect(harness.server.peer.verified);
    try testing.expect(!harness.server.peer.empty);
    try testing.expectEqual(
        backend.SignatureScheme.ecdsa_secp256r1_sha256,
        harness.server.peer.scheme.?,
    );
    // And in the other direction, unchanged.
    try testing.expect(harness.client.peer.verified);

    // Working keys after all that: the client-auth messages are in the
    // transcript both Finisheds MAC, so a mismatch here is the two ends
    // disagreeing about §4.4's context rather than about the data.
    const ping = try harness.client.sendApplicationData("mutual", &buffers.client_out);
    const event = (try harness.server.handleRecord(ping, &buffers.server_out)).?;
    try testing.expectEqualSlices(u8, "mutual", event.application_data);
}

test "§4.4.2: a client with no certificate answers, and §4.4.2.1 judges it" {
    // Our own client this time, not the test client — the same empty
    // certificate_list, produced by the machine an embedder would ship.
    for ([_]bool{ true, false }) |require| {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        try harness.init(.{ .client_auth = .{ .require = require } });
        defer harness.deinit();

        if (require) {
            try testing.expectError(error.CertificateRequired, harness.connect(&buffers));
        } else {
            try harness.connect(&buffers);
            try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
            // Completed, and nobody was authenticated.
            try testing.expect(!harness.server.peer.verified);
            try testing.expect(harness.server.peer.empty);
        }
    }
}

test "§4.3.2: an unsolicited CertificateRequest declines rather than panicking" {
    // The client under test configured no credentials and so no
    // `client_auth_flight` — which is every client that never thought
    // about mTLS, and exactly the client a server can send an
    // unsolicited CertificateRequest to. Building the refusal into that
    // empty buffer was a reachable assertion: a remote panic, found by
    // BoGo's `CertificateRequestInResumption` and pinned here.
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{ .client_auth = .{ .require = false } });
    defer harness.deinit();

    // No credentials, no flight buffer, and the handshake still
    // completes — with nobody authenticated, which `require = false`
    // permits and the server records.
    try testing.expectEqual(@as(usize, 0), harness.client.config.client_auth_flight.len);
    try harness.connect(&buffers);
    try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);
    try testing.expect(harness.client.certificate_requested);
    try testing.expect(harness.server.peer.empty);
    try testing.expect(!harness.server.peer.verified);
}

test "§4.3.2: a resumed session refuses an unsolicited client certificate" {
    // The authentication gap the review found. §4.3.2 forbids a
    // CertificateRequest under a PSK, so a resumed handshake never asks
    // — and `checkClientAuth` returns early for exactly that reason. The
    // message arms gated on the *config* rather than on `resumed`, so a
    // client holding any ticket could volunteer a self-signed
    // certificate and have `peer.verified` come out true for an identity
    // nobody requested and `require` never judged.
    //
    // Worse than silent: the field's own documentation tells an embedder
    // it may read `peer.verified` on a resumed connection precisely
    // because client auth is skipped there.
    var store: TicketStore = undefined;
    var buffers: Buffers = .{};

    var first: Harness = undefined;
    try first.init(.{ .store = &store, .client_auth = .{ .require = false } });
    defer first.deinit();
    try first.connect(&buffers);
    const resumption = try issueTicket(&first, &buffers, &store);

    var second: Harness = undefined;
    try second.init(.{
        .store = &store,
        .resume_session = resumption,
        .client_auth = .{ .require = false },
    });
    defer second.deinit();
    try second.connect(&buffers);

    try testing.expect(second.server.resumed);
    // Nothing was asked for, so nothing may have been proven.
    try testing.expect(!second.server.peer.verified);
    try testing.expect(!second.server.peer.seen);
    // And the client knows it was never asked.
    try testing.expect(!second.client.certificate_requested);
}

test "§4.4: the client bounds its flight's message count, not the server" {
    // `assert(messages_seen < 8)` assumed EncryptedExtensions,
    // Certificate, CertificateVerify, Finished. Neither the first nor
    // the third was single-shot, so a server could repeat either until
    // the count walked into the assertion — a remote panic by two
    // separate routes. Both forged here under genuine handshake keys,
    // because our own server sends each exactly once.
    const Shape = enum { extensions, verify };
    for ([_]Shape{ .extensions, .verify }) |shape| {
        var buffers: Buffers = .{};
        var harness: Harness = undefined;
        // `.insecure_no_verification` for the CertificateVerify case,
        // and for the same reason the server-side test uses it: the
        // checker records each message without looking at it, so the
        // *first* copy succeeds and the second reaches the guard. Under
        // the ordinary policy the first fails on its signature and the
        // machine is dead before the count can matter.
        try harness.init(.{
            .certificate_policy = if (shape == .verify)
                .insecure_no_verification
            else
                .leaf_signature,
        });
        defer harness.deinit();

        const hello = harness.client.start(&buffers.client_out);
        const flight = (try harness.server.handleRecord(hello, &buffers.server_out)).?;
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);

        var forger = try serverFlightProtector(
            &client_x25519_private,
            hello,
            server_hello_record,
        );
        defer forger.deinit();
        var plaintext: [4096]u8 = undefined;
        var forged: [record.wire_record_bytes_max]u8 = undefined;

        const extensions = server_messages.encryptedExtensions(&plaintext, "http/1.1", false);
        _ = try harness.client.handleRecord(
            try forger.seal(.handshake, extensions, &forged),
            &buffers.scratch,
        );

        switch (shape) {
            // A second EncryptedExtensions, which §4.4 does not have.
            .extensions => {
                const again = server_messages.encryptedExtensions(&plaintext, "http/1.1", false);
                try testing.expectError(
                    error.UnexpectedMessage,
                    harness.client.handleRecord(
                        try forger.seal(.handshake, again, &forged),
                        &buffers.scratch,
                    ),
                );
            },
            // A Certificate, then two CertificateVerifies. The first is
            // refused on its signature long before the count matters —
            // which is the point: the guard has to come *before* the
            // verification for the second one to be unreachable.
            .verify => {
                const chain = server_messages.certificateChain(&plaintext, harness.credentials.chain());
                _ = try harness.client.handleRecord(
                    try forger.seal(.handshake, chain, &forged),
                    &buffers.scratch,
                );
                var body: [128]u8 = undefined;
                const verify = server_messages.certificateVerify(&body, 0x0403, &(.{0xa5} ** 64));
                // The first is accepted — the policy declines to check
                // it — which is what leaves a second one to refuse.
                _ = try harness.client.handleRecord(
                    try forger.seal(.handshake, verify, &forged),
                    &buffers.scratch,
                );
                try testing.expectError(
                    error.UnexpectedMessage,
                    harness.client.handleRecord(
                        try forger.seal(.handshake, verify, &forged),
                        &buffers.scratch,
                    ),
                );
            },
        }
    }
}
