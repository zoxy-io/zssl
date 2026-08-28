//! Slice 4's end-to-end: the production `ClientHandshake` against the
//! production `ServerHandshake` — both real machines, no test client.
//! Covers the full origination path zoxy needs for upstreams: SNI, ALPN,
//! leaf verification, tickets captured through the client's event
//! surface, resumption, §4.6.3 KeyUpdate in both directions with the
//! kTLS export tracking generations, and the client's structural refusal
//! of HelloRetryRequest.

const std = @import("std");
const testing = std.testing;

const ClientHandshake = @import("ClientHandshake.zig");
const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const cipher_suite = @import("cipher_suite.zig");
const record = @import("record.zig");
const backend = @import("crypto/backend_openssl.zig");
const key_schedule = @import("key_schedule.zig");
const protect = @import("protect.zig");
const client_hello_mod = @import("client_hello.zig");
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
    ) ?u8 {
        _ = obfuscated_age;
        const store: *TicketStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, store.identity[0..store.identity_bytes], identity)) return null;
        psk_out.* = store.psk;
        return 32;
    }
};

const Harness = struct {
    chain_storage: [Credentials.chain_bytes_max]u8,
    credentials: Credentials,
    server_reassembly: [8192]u8,
    flight: [Credentials.chain_bytes_max + 1024]u8,
    client_reassembly: [16384]u8,
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
        leaf: enum { ecdsa_p256, rsa_2048 } = .ecdsa_p256,
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
            .reassembly = &harness.client_reassembly,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.client.deinit();
        harness.server.deinit();
        harness.credentials.deinit();
    }

    /// Drive the handshake to `connected` on both machines.
    fn connect(harness: *Harness, buffers: *Buffers) !void {
        const hello = harness.client.start(&buffers.client_out);
        const flight = try harness.server.handleRecord(hello, &buffers.server_out);
        try testing.expectEqual(std.meta.activeTag(flight), .send);

        var reply_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
        var reply_bytes: usize = 0;
        var index: usize = 0;
        var count: u8 = 0;
        while (index < flight.send.len) : (count += 1) {
            try testing.expect(count < 8);
            const one = recordAt(flight.send, index);
            const event = try harness.client.handleRecord(one, &buffers.scratch);
            switch (event) {
                .none => {},
                .connected => |bytes| {
                    @memcpy(reply_storage[0..bytes.len], bytes);
                    reply_bytes = bytes.len;
                },
                else => return error.TestUnexpectedResult,
            }
            index += one.len;
        }
        try testing.expect(reply_bytes >= 1);
        try testing.expectEqual(ClientHandshake.State.connected, harness.client.state);

        index = 0;
        count = 0;
        var final: ServerHandshake.Event = .none;
        while (index < reply_bytes) : (count += 1) {
            try testing.expect(count < 8);
            const one = recordAt(reply_storage[0..reply_bytes], index);
            final = try harness.server.handleRecord(one, &buffers.server_out);
            index += one.len;
        }
        try testing.expectEqual(std.meta.activeTag(final), .connected);
        try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
    }
};

fn recordAt(bytes: []const u8, index: usize) []const u8 {
    const length = std.mem.readInt(u16, bytes[index + 3 ..][0..2], .big);
    return bytes[index..][0 .. record.header_bytes + length];
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

test "production client ↔ server: handshake, data, ticket capture, resumption" {
    var buffers: Buffers = .{};

    // Session one, full handshake with leaf verification and ALPN.
    var first: Harness = undefined;
    try first.init(.{});
    defer first.deinit();
    try first.connect(&buffers);
    try testing.expect(first.client.certificate_verified);
    try testing.expectEqualSlices(u8, "http/1.1", first.client.alpnSelected().?);
    try testing.expect(!first.client.resumed);
    try testing.expect(!first.server.resumed);

    // Application data in both directions.
    const ping = try first.client.sendApplicationData("ping from origin client", &buffers.client_out);
    const ping_event = try first.server.handleRecord(ping, &buffers.server_out);
    try testing.expectEqualSlices(u8, "ping from origin client", ping_event.application_data);
    const pong = try first.server.sendApplicationData("pong", &buffers.server_out);
    const pong_event = try first.client.handleRecord(pong, &buffers.scratch);
    try testing.expectEqualSlices(u8, "pong", pong_event.application_data);

    // A ticket travels server → client through the event surface; the
    // client derives the PSK for it from its own resumption_master.
    var store: TicketStore = undefined;
    var psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const server_psk = first.server.resumptionPsk(&.{0x0a}, &psk_buffer);
    @memset(&store.psk, 0);
    @memcpy(store.psk[0..server_psk.len], server_psk);
    @memcpy(store.identity[0..13], "sealed-by-us!");
    store.identity_bytes = 13;
    const sealed = try first.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 0x5eed,
        .ticket_nonce = &.{0x0a},
        .ticket = "sealed-by-us!",
    }, &buffers.server_out);
    const ticket_event = try first.client.handleRecord(sealed, &buffers.scratch);
    try testing.expectEqual(std.meta.activeTag(ticket_event), .ticket);
    try testing.expectEqual(@as(u32, 3600), ticket_event.ticket.lifetime_s);
    var resumption: ClientHandshake.Resumption = .{
        .identity = "sealed-by-us!",
        .obfuscated_age = ticket_event.ticket.age_add,
        .psk = undefined,
        .psk_bytes = 32,
    };
    var client_psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const client_psk = first.client.resumptionPsk(ticket_event.ticket.nonce, &client_psk_buffer);
    @memset(&resumption.psk, 0);
    @memcpy(resumption.psk[0..client_psk.len], client_psk);
    // Both ends derived the same PSK from their own resumption_master.
    try testing.expectEqualSlices(u8, server_psk, client_psk);

    // Clean close, server first this time.
    const close_record = try first.server.sendClose(&buffers.server_out);
    const close_event = try first.client.handleRecord(close_record, &buffers.scratch);
    try testing.expectEqual(std.meta.activeTag(close_event), .closed);

    // Session two: resumed on the captured ticket, no certificate leg.
    var second: Harness = undefined;
    try second.init(.{ .store = &store, .resume_session = resumption });
    defer second.deinit();
    try second.connect(&buffers);
    try testing.expect(second.server.resumed);
    try testing.expect(second.client.resumed);
    try testing.expect(!second.client.certificate_verified);
    const echo = try second.client.sendApplicationData("resumed", &buffers.client_out);
    const echo_event = try second.server.handleRecord(echo, &buffers.server_out);
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
    const update_event = try harness.server.handleRecord(update, &buffers.server_out);
    try testing.expectEqual(std.meta.activeTag(update_event), .send);
    const ack_event = try harness.client.handleRecord(update_event.send, &buffers.scratch);
    try testing.expectEqual(std.meta.activeTag(ack_event), .none);

    // Every direction moved to generation 1 and both sides agree.
    const after = harness.client.exportKeyMaterial(.transmit);
    try testing.expect(!std.mem.eql(u8, before.key[0..before.key_bytes], after.key[0..after.key_bytes]));
    try expectExportAgreement(&harness.server, &harness.client);

    // Traffic still flows under the new generation, both ways.
    const ping = try harness.client.sendApplicationData("post-update ping", &buffers.client_out);
    const ping_event = try harness.server.handleRecord(ping, &buffers.server_out);
    try testing.expectEqualSlices(u8, "post-update ping", ping_event.application_data);
    const pong = try harness.server.sendApplicationData("post-update pong", &buffers.server_out);
    const pong_event = try harness.client.handleRecord(pong, &buffers.scratch);
    try testing.expectEqualSlices(u8, "post-update pong", pong_event.application_data);

    // Server-initiated, no rotation requested back: only its transmit
    // side and the client's receive side move.
    const quiet_update = try harness.server.sendKeyUpdate(false, &buffers.server_out);
    const quiet_event = try harness.client.handleRecord(quiet_update, &buffers.scratch);
    try testing.expectEqual(std.meta.activeTag(quiet_event), .none);
    try expectExportAgreement(&harness.server, &harness.client);
    const again = try harness.server.sendApplicationData("gen2", &buffers.server_out);
    const again_event = try harness.client.handleRecord(again, &buffers.scratch);
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
        const flight = try harness.server.handleRecord(hello, &buffers.server_out);
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);
        try testing.expectEqual(ClientHandshake.State.awaiting_flight, harness.client.state);

        // Forge a flight under the genuine handshake keys.
        var forger = try serverFlightProtector(
            &client_x25519_private,
            hello,
            server_hello_record,
        );
        defer forger.deinit();
        var plaintext: [4096]u8 = undefined;
        var used: usize = 0;
        const extensions = server_messages.encryptedExtensions(plaintext[used..], "http/1.1");
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

test "the client refuses HelloRetryRequest, structurally" {
    var buffers: Buffers = .{};
    var harness: Harness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    _ = harness.client.start(&buffers.client_out);

    var message_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = server_messages.helloRetryRequest(&message_buffer, &(.{0x44} ** 32), .aes_128_gcm_sha256, client_hello_mod.group_x25519);
    var wire_buffer: [record.header_bytes + server_messages.server_hello_bytes_max]u8 = undefined;
    record.writeHeader(
        .{ .content_type = .handshake, .length = @intCast(retry.len) },
        wire_buffer[0..record.header_bytes],
    );
    @memcpy(wire_buffer[record.header_bytes..][0..retry.len], retry);
    try testing.expectError(
        error.HandshakeFailure,
        harness.client.handleRecord(wire_buffer[0 .. record.header_bytes + retry.len], &buffers.scratch),
    );
    try testing.expectEqual(ClientHandshake.State.failed, harness.client.state);
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
    try testing.expect(!harness.client.certificate_verified);
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
    const flight = try harness.server.handleRecord(hello, &buffers.server_out);
    const server_hello_record = recordAt(flight.send, 0);
    _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);
    try testing.expectEqual(ClientHandshake.State.awaiting_flight, harness.client.state);

    var forger = try serverFlightProtector(
        &client_x25519_private,
        hello,
        server_hello_record,
    );
    defer forger.deinit();
    var plaintext: [4096]u8 = undefined;
    // "http/1.1" was never in the offer — only "h2" was.
    const extensions = server_messages.encryptedExtensions(&plaintext, "http/1.1");
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
    try testing.expect(!harness.client.certificate_verified);
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
        try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
        const event = try harness.client.handleRecord(sealed, &buffers.scratch);
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
    const flight = try harness.server.handleRecord(hello, &buffers.server_out);
    const server_hello = recordAt(flight.send, 0);
    _ = try harness.client.handleRecord(server_hello, &buffers.scratch);
    try testing.expectEqual(ClientHandshake.State.awaiting_flight, harness.client.state);

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
    try testing.expect(harness.client.certificate_verified);

    const ping = try harness.client.sendApplicationData("rsa", &buffers.client_out);
    const event = try harness.server.handleRecord(ping, &buffers.server_out);
    try testing.expectEqualSlices(u8, "rsa", event.application_data);
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
        const flight = try harness.server.handleRecord(hello, &buffers.server_out);
        const server_hello_record = recordAt(flight.send, 0);
        _ = try harness.client.handleRecord(server_hello_record, &buffers.scratch);
        try testing.expectEqual(ClientHandshake.State.awaiting_flight, harness.client.state);

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
            const event = try harness.server.handleRecord(one, &buffers.server_out);
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
    const flight = try harness.server.handleRecord(hello, &buffers.server_out);
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
        const flight = try harness.server.handleRecord(hello, &buffers.server_out);
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
