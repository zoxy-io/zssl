//! End-to-end handshakes: `TestClient` against `ServerHandshake`, in
//! memory. The client file says what this does and does not prove; the
//! scenarios here are the state-machine facts — 1-RTT, fragmentation,
//! HelloRetryRequest, ALPN, kTLS export, and the failure paths.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const backend = @import("crypto/backend_openssl.zig");
const record = @import("record.zig");
const test_client = @import("test_client.zig");

const Client = test_client.TestClient(.aes_128_gcm_sha256);

const client_x25519_private = [_]u8{0x11} ** 31 ++ [_]u8{0x42};
const server_key_share_private = [_]u8{0x99} ** 47 ++ [_]u8{0x24};
const server_random = [_]u8{0x5c} ** 32;

const Harness = struct {
    chain_storage: [Credentials.chain_bytes_max]u8,
    credentials: Credentials,
    reassembly: [8192]u8,
    flight: [Credentials.chain_bytes_max + 1024]u8,
    server: ServerHandshake,

    fn init(harness: *Harness, alpn: ?[]const u8) !void {
        return harness.initWith(alpn, null);
    }

    fn initWith(
        harness: *Harness,
        alpn: ?[]const u8,
        client_auth: ?ServerHandshake.ClientAuth,
    ) !void {
        harness.credentials = try Credentials.load(
            @embedFile("testdata/cert.pem"),
            @embedFile("testdata/key.pem"),
            &harness.chain_storage,
            true,
        );
        harness.server = ServerHandshake.init(&.{
            .credentials = &harness.credentials,
            .server_random = server_random,
            .key_share_private = server_key_share_private,
            .alpn = alpn,
            .client_auth = client_auth,
            .reassembly = &harness.reassembly,
            .flight = &harness.flight,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.server.deinit();
        harness.credentials.deinit();
    }
};

/// Feed a byte run that may hold several whole records; one actionable
/// event per run is the tests' invariant.
fn feedRecords(server: *ServerHandshake, bytes: []const u8, out: []u8) !ServerHandshake.Event {
    var index: usize = 0;
    var final: ?ServerHandshake.Event = null;
    var count: u8 = 0;
    while (index < bytes.len) : (count += 1) {
        try testing.expect(count < 8);
        const length = std.mem.readInt(u16, bytes[index + 3 ..][0..2], .big);
        const one = bytes[index..][0 .. record.header_bytes + length];
        if (try server.handleRecord(one, out)) |event| {
            try testing.expect(final == null);
            final = event;
        }
        index += one.len;
    }
    try testing.expectEqual(bytes.len, index);
    try testing.expect(final != null);
    return final.?;
}

test "full 1-RTT: ALPN, app data both ways, kTLS export, clean close" {
    var harness: Harness = undefined;
    try harness.init("http/1.1");
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{
        .session_id = &(.{0xab} ** 32),
        .alpn = "http/1.1",
        .server_name = "spike.zoxy.test",
    });
    defer client.deinit();
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    const hello = client.helloRecord(&client_out);
    const flight = (try harness.server.handleRecord(hello, &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);

    const reply = try client.absorb(flight.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);
    try testing.expect(client.certificate_verified);
    try testing.expect(client.alpn_selected);

    const done = try feedRecords(&harness.server, reply.connected, &server_out);
    try testing.expectEqual(std.meta.activeTag(done), .connected);
    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);

    // Application data, both directions.
    const ping = try client.sendApplicationData("ping", &client_out);
    const ping_event = (try harness.server.handleRecord(ping, &server_out)).?;
    try testing.expectEqualSlices(u8, "ping", ping_event.application_data);
    const pong = try harness.server.sendApplicationData("pong", &server_out);
    const pong_event = try client.absorb(pong, &client_out);
    try testing.expectEqualSlices(u8, "pong", pong_event.application_data);

    // kTLS export must agree with what the client derived on its own:
    // the server's transmit keys are the client's receive keys.
    const transmit = harness.server.exportKeyMaterial(.transmit);
    try testing.expectEqualSlices(u8, &client.receive_keys.key, transmit.key[0..transmit.key_bytes]);
    try testing.expectEqualSlices(u8, &client.receive_keys.iv, &transmit.static_iv);
    try testing.expectEqual(@as(u64, 1), transmit.next_sequence); // "pong" went out.
    const receive = harness.server.exportKeyMaterial(.receive);
    try testing.expectEqualSlices(u8, &client.transmit_keys.key, receive.key[0..receive.key_bytes]);

    // Clean shutdown, client first — and clean means both directions.
    // §6.1 closes one at a time, so the server's read side goes first
    // and its write side is still open, which is what lets it answer.
    const close_record = try client.sendClose(&client_out);
    const close_event = (try harness.server.handleRecord(close_record, &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(close_event), .closed);
    try testing.expectEqual(ServerHandshake.State.close_received, harness.server.state);
    try testing.expect(harness.server.writable());
    try testing.expect(!harness.server.readable());

    // Answering is the ordinary thing to do, and used to be an abort.
    _ = try harness.server.sendClose(&server_out);
    try testing.expectEqual(ServerHandshake.State.closed, harness.server.state);
    try testing.expect(!harness.server.writable()); // Both halves of the round trip, with two real handshakes on either
    // end, live in client_server_test.zig — the reference client here is
    // a test peer rather than a second implementation of §6.1.
}

test "a ClientHello fragmented across three records reassembles" {
    var harness: Harness = undefined;
    try harness.init(null);
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{});
    defer client.deinit();
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    const hello = client.helloRecord(&client_out);
    const payload = hello[record.header_bytes..];
    const third = payload.len / 3;
    const cuts = [_][2]usize{
        .{ 0, third },
        .{ third, 2 * third },
        .{ 2 * third, payload.len },
    };
    var flight: ?ServerHandshake.Event = null;
    for (cuts, 0..) |cut, index| {
        var fragment: [record.wire_record_bytes_max]u8 = undefined;
        const body = payload[cut[0]..cut[1]];
        record.writeHeader(
            .{ .content_type = .handshake, .length = @intCast(body.len) },
            fragment[0..record.header_bytes],
        );
        @memcpy(fragment[record.header_bytes..][0..body.len], body);
        const event = try harness.server.handleRecord(
            fragment[0 .. record.header_bytes + body.len],
            &server_out,
        );
        if (index < cuts.len - 1) {
            try testing.expect(event == null);
        } else {
            flight = event;
        }
    }
    // The reassembled hello produces a flight the client accepts whole —
    // transcript agreement is the proof the fragments reunited exactly.
    const reply = try client.absorb(flight.?.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);
    const done = try feedRecords(&harness.server, reply.connected, &server_out);
    try testing.expectEqual(std.meta.activeTag(done), .connected);
}

test "HelloRetryRequest: no usable share, retry, complete" {
    var harness: Harness = undefined;
    try harness.init(null);
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{
        .offer_x25519_share = false,
        .offer_unsupported_decoy = true,
    });
    defer client.deinit();
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    const first_hello = client.helloRecord(&client_out);
    const retry = (try harness.server.handleRecord(first_hello, &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(retry), .send);
    try testing.expectEqual(ServerHandshake.State.awaiting_retry_client_hello, harness.server.state);

    const second_hello = try client.absorb(retry.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(second_hello), .send);
    try testing.expect(client.saw_retry);

    const flight = try feedRecords(&harness.server, second_hello.send, &server_out);
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    const reply = try client.absorb(flight.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);
    try testing.expect(client.certificate_verified);
    const done = try feedRecords(&harness.server, reply.connected, &server_out);
    try testing.expectEqual(std.meta.activeTag(done), .connected);
}

test "failure paths fail closed" {
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    // No common cipher suite: an offer of one TLS 1.2 suite only.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{ .suites_wire = &.{ 0xc0, 0x2f } });
        defer client.deinit();
        const hello = client.helloRecord(&client_out);
        try testing.expectError(error.HandshakeFailure, harness.server.handleRecord(hello, &server_out));
        try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
    }

    // ALPN offered with no overlap is fatal (RFC 7301 §3.2).
    {
        var harness: Harness = undefined;
        try harness.init("http/1.1");
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{ .alpn = "h2" });
        defer client.deinit();
        const hello = client.helloRecord(&client_out);
        try testing.expectError(error.NoApplicationProtocol, harness.server.handleRecord(hello, &server_out));
    }

    // A tampered client Finished dies as an AEAD failure, pre-verification.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{ .send_change_cipher_spec = false });
        defer client.deinit();
        const hello = client.helloRecord(&client_out);
        const flight = (try harness.server.handleRecord(hello, &server_out)).?;
        const reply = try client.absorb(flight.send, &client_out);
        var tampered: [2 * record.wire_record_bytes_max]u8 = undefined;
        @memcpy(tampered[0..reply.connected.len], reply.connected);
        tampered[reply.connected.len - 1] ^= 0x01;
        try testing.expectError(
            error.AuthenticationFailed,
            harness.server.handleRecord(tampered[0..reply.connected.len], &server_out),
        );
        try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
    }

    // A second ClientHello after connecting is a peer talking past the
    // handshake, not a renegotiation.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{});
        defer client.deinit();
        const hello = client.helloRecord(&client_out);
        const flight = (try harness.server.handleRecord(hello, &server_out)).?;
        const reply = try client.absorb(flight.send, &client_out);
        const done = try feedRecords(&harness.server, reply.connected, &server_out);
        try testing.expectEqual(std.meta.activeTag(done), .connected);
        var second = Client.init(&client_x25519_private, &.{});
        defer second.deinit();
        const replay = second.helloRecord(&client_out);
        try testing.expectError(error.UnexpectedMessage, harness.server.handleRecord(replay, &server_out));
    }
}

test "the server negotiates whichever group the client offers a share for" {
    // x25519 is covered everywhere else; these are the two that arrived
    // with secp256r1/secp384r1 support, and the point is that the whole
    // handshake completes on them — ServerHello share, key schedule,
    // Finished — not merely that the ECDH agrees.
    for ([_]backend.Group{ .secp256r1, .secp384r1 }) |group| {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{ .group = group });
        defer client.deinit();

        var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
        var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

        const hello = client.helloRecord(&client_out);
        const flight = (try harness.server.handleRecord(hello, &server_out)).?;
        try testing.expectEqual(std.meta.activeTag(flight), .send);
        // No HelloRetryRequest: the share was usable as offered.
        try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);
        try testing.expectEqual(group, harness.server.key_share_group);

        const reply = try client.absorb(flight.send, &client_out);
        try testing.expectEqual(std.meta.activeTag(reply), .connected);
        try testing.expect(client.certificate_verified);
        const done = try feedRecords(&harness.server, reply.connected, &server_out);
        try testing.expectEqual(std.meta.activeTag(done), .connected);
    }
}

test "a share whose point is not on the curve is refused, not negotiated" {
    var harness: Harness = undefined;
    try harness.init(null);
    defer harness.deinit();
    // A P-256 group with a garbage point: the length is right, so the
    // parser admits it and the refusal has to come from the key
    // exchange itself (§4.2.8.2).
    var client = Client.init(&client_x25519_private, &.{
        .offer_x25519_share = false,
        .offer_bogus_p256_share = true,
    });
    defer client.deinit();
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    const hello = client.helloRecord(&client_out);
    try testing.expectError(
        error.IdentityElement,
        harness.server.handleRecord(hello, &server_out),
    );
    try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
}

test "§9.2: an omitted key_share is missing_extension, an empty one is a retry" {
    // The two are one byte apart on the wire and mean opposite things.
    // §4.2.8 lets a client send an empty `client_shares` to ask the
    // server to pick a group, which costs a round trip and is answered
    // with HelloRetryRequest. §9.2 requires the extension to be *there*
    // for any hello attempting (EC)DHE, and a server receiving one
    // without it "MUST abort the handshake with a missing_extension
    // alert". A `key_share_count` of zero cannot tell them apart.
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{ .omit_key_share = true });
        defer client.deinit();
        try testing.expectError(
            error.MissingExtension,
            harness.server.handleRecord(client.helloRecord(&client_out), &server_out),
        );
    }

    // The control: the extension present but offering only a group we do
    // not hold is the §4.2.8 case, and must still earn a retry.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{
            .offer_x25519_share = false,
            .offer_unsupported_decoy = true,
        });
        defer client.deinit();
        const retry = (try harness.server.handleRecord(client.helloRecord(&client_out), &server_out)).?;
        try testing.expectEqual(std.meta.activeTag(retry), .send);
        try testing.expectEqual(
            ServerHandshake.State.awaiting_retry_client_hello,
            harness.server.state,
        );
    }
}

test "§4.2.9 and §4.6.1: psk_key_exchange_modes gates both the offer and the ticket" {
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    // §9.2 lists psk_key_exchange_modes among what a TLS 1.3 hello must
    // carry, and §4.2.9 makes it mandatory beside a PSK: "In order to use
    // PSKs, clients MUST also send a psk_key_exchange_modes extension".
    // An offer with no modes leaves nothing to select, and answering it
    // with a full handshake — which zssl did — hides a malformed offer
    // behind a working connection.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var ticket: test_client.Ticket = .{
            .lifetime_s = 3600,
            .age_add = 0,
            .nonce = undefined,
            .nonce_bytes = 1,
            .ticket = undefined,
            .ticket_bytes = 4,
            .psk = undefined,
            .psk_bytes = 32,
        };
        ticket.nonce[0] = 0x01;
        @memcpy(ticket.ticket[0..4], "psk!");
        @memset(ticket.psk[0..32], 0x5a);
        var client = Client.init(&client_x25519_private, &.{
            .resume_with = &ticket,
            .omit_psk_modes = true,
        });
        defer client.deinit();
        try testing.expectError(
            error.MissingExtension,
            harness.server.handleRecord(client.helloRecord(&client_out), &server_out),
        );
    }

    // §4.2.9: a client that advertised modes and left ours out of them
    // must ignore any ticket we send, so the library refuses to mint one
    // rather than leaving it to the embedder to remember. 0x1a is the
    // byte BoGo uses: a mode that is neither psk_ke nor psk_dhe_ke.
    //
    // Advertising *no* modes is deliberately not this case — the RFC
    // forbids tickets "not compatible with the advertised modes", and a
    // hello with none has nothing to be incompatible with. Enforcing the
    // wider rule broke ten of tlsfuzzer's `connection-abort`
    // conversations, which wait on a ticket their hello never asked
    // about, and that is a legitimate client.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{ .psk_mode_byte = 0x1a });
        defer client.deinit();

        const flight = (try harness.server.handleRecord(client.helloRecord(&client_out), &server_out)).?;
        const reply = try client.absorb(flight.send, &client_out);
        const done = try feedRecords(&harness.server, reply.connected, &server_out);
        try testing.expectEqual(std.meta.activeTag(done), .connected);

        try testing.expect(!harness.server.ticketPermitted());
        // The control: no modes advertised at all is permitted, because
        // there is nothing the ticket can contradict.
        {
            var permissive: Harness = undefined;
            try permissive.init(null);
            defer permissive.deinit();
            var bare = Client.init(&client_x25519_private, &.{ .omit_psk_modes = true });
            defer bare.deinit();
            var out: [2 * record.wire_record_bytes_max]u8 = undefined;
            var scratch: [2 * record.wire_record_bytes_max]u8 = undefined;
            const bare_flight = (try permissive.server.handleRecord(bare.helloRecord(&out), &scratch)).?;
            const bare_reply = try bare.absorb(bare_flight.send, &out);
            _ = try feedRecords(&permissive.server, bare_reply.connected, &scratch);
            try testing.expect(permissive.server.ticketPermitted());
        }
        try testing.expectError(error.TicketNotPermitted, harness.server.sendNewSessionTicket(&.{
            .lifetime_s = 3600,
            .age_add = 0,
            .ticket_nonce = &.{0x01},
            .ticket = "unusable",
        }, &server_out));
        // The refusal is about the ticket, not the connection: a peer
        // that cannot resume is still a peer we are talking to.
        try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
    }
}

/// A rejected-early-data record as a peer actually sends one: an
/// application_data header over bytes we hold no key for. BoGo's
/// `sendFakeEarlyData` writes exactly this — a header and zeros — which
/// is fair, because to the server every byte of it is undecryptable
/// either way.
fn earlyDataRecord(out: []u8, body_bytes: u16) []const u8 {
    assert(out.len >= record.header_bytes + body_bytes);
    record.writeHeader(
        .{ .content_type = .application_data, .length = body_bytes },
        out[0..record.header_bytes],
    );
    @memset(out[record.header_bytes..][0..body_bytes], 0);
    return out[0 .. record.header_bytes + body_bytes];
}

test "§4.2.10: early data we declined is skipped, and the handshake completes" {
    // The client offers 0-RTT, we say nothing — which is how a server
    // declines — and it sends the data anyway, because our flight has
    // not reached it yet. Those records cannot be opened with any key we
    // hold, so refusing them would report a fault the peer did not
    // commit. §4.2.10: "the server ... MUST skip past".
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var harness: Harness = undefined;
    try harness.init(null);
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{ .offer_early_data = true });
    defer client.deinit();

    const flight = (try harness.server.handleRecord(client.helloRecord(&client_out), &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    try testing.expect(harness.server.early_data_offered);

    // Two of them, to prove the window is a window and not one record's
    // grace. Neither produces an event.
    var early_storage: [record.wire_record_bytes_max]u8 = undefined;
    for (0..2) |_| {
        const early = earlyDataRecord(&early_storage, 4);
        try testing.expect(try harness.server.handleRecord(early, &server_out) == null);
    }
    try testing.expectEqual(@as(u32, 2 * 4), harness.server.early_data_skipped);

    // And the handshake the early data was riding in front of finishes.
    var reply_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
    const reply = try client.absorb(flight.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);
    @memcpy(reply_storage[0..reply.connected.len], reply.connected);
    const done = try feedRecords(&harness.server, reply_storage[0..reply.connected.len], &server_out);
    try testing.expectEqual(std.meta.activeTag(done), .connected);
    // The window shut on the first record that opened — the Finished —
    // so early data arriving behind it is ciphertext we failed to read.
    try testing.expect(!harness.server.early_data_offered);
}

test "§4.2.10: more skipped early data than the ceiling ends the connection" {
    // Discarding is work, and a peer that can buy unbounded work for the
    // price of a header is the shape flood.zig exists to refuse. The
    // ceiling counts payload bytes — what §4.2.10 measures early data in
    // — with a floor of one a record, so that a peer sending nothing but
    // headers still spends the budget.
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var harness: Harness = undefined;
    try harness.init(null);
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{ .offer_early_data = true });
    defer client.deinit();
    _ = (try harness.server.handleRecord(client.helloRecord(&client_out), &server_out)).?;

    // The boundary from both sides, and the count accumulating across
    // records rather than resetting per record. Exactly the ceiling is
    // allowed — a client that sent 2^14 was sending what a server
    // advertising §4.2.10's own example limit would have invited — and
    // the byte after it is not.
    var early_storage: [record.wire_record_bytes_max]u8 = undefined;
    for (0..2) |_| {
        const half = earlyDataRecord(&early_storage, 8192);
        try testing.expect(try harness.server.handleRecord(half, &server_out) == null);
    }
    try testing.expectEqual(@as(u32, 16384), harness.server.early_data_skipped);
    try testing.expectError(
        error.TooMuchSkippedEarlyData,
        harness.server.handleRecord(earlyDataRecord(&early_storage, 1), &server_out),
    );
}

test "§4.2.10: an empty early-data record spends the budget too" {
    // §5.1 lets an application_data record carry nothing, and a ceiling
    // that counts only payload counts those as free — so a peer that
    // sends nothing but headers holds the window open forever at five
    // bytes a turn, which is the very thing the ceiling exists to
    // refuse. Each record costs a byte of budget at least.
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var harness: Harness = undefined;
    try harness.init(null);
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{ .offer_early_data = true });
    defer client.deinit();
    _ = (try harness.server.handleRecord(client.helloRecord(&client_out), &server_out)).?;

    var early_storage: [record.header_bytes]u8 = undefined;
    const empty = earlyDataRecord(&early_storage, 0);
    try testing.expectEqual(@as(usize, record.header_bytes), empty.len);
    try testing.expect(try harness.server.handleRecord(empty, &server_out) == null);
    try testing.expectEqual(@as(u32, 1), harness.server.early_data_skipped);

    // And the run of them ends, rather than going on for as long as the
    // peer cares to keep sending. Bounded by the ceiling itself, which
    // is what the loop is proving.
    var sent: u32 = 1;
    while (sent < 16384) : (sent += 1) {
        try testing.expect(try harness.server.handleRecord(empty, &server_out) == null);
    }
    try testing.expectEqual(@as(u32, 16384), harness.server.early_data_skipped);
    try testing.expectError(
        error.TooMuchSkippedEarlyData,
        harness.server.handleRecord(empty, &server_out),
    );
}

test "§4.2.10: early_data carries no body in a ClientHello, and none on a retry" {
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    // §4.2.10 gives the extension `Empty` here. A body is a message that
    // did not decode, whatever it holds — and we read the grammar even
    // though we decline everything it offers.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{
            .offer_early_data = true,
            .early_data_body_bytes = 1,
        });
        defer client.deinit();
        try testing.expectError(
            error.MalformedExtension,
            harness.server.handleRecord(client.helloRecord(&client_out), &server_out),
        );
    }

    // §4.1.2's exception list requires "removing the early_data
    // extension ... if one was present. Early data is not permitted
    // after a HelloRetryRequest." A second hello that kept it is one we
    // may not answer.
    {
        var harness: Harness = undefined;
        try harness.init(null);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{
            .offer_x25519_share = false,
            .offer_early_data = true,
        });
        defer client.deinit();
        const retry = (try harness.server.handleRecord(client.helloRecord(&client_out), &server_out)).?;
        try testing.expectEqual(std.meta.activeTag(retry), .send);
        const second = try client.absorb(retry.send, &client_out);
        try testing.expectEqual(std.meta.activeTag(second), .send);
        try testing.expectError(
            error.IllegalRetry,
            harness.server.handleRecord(second.send, &server_out),
        );
    }
}

test "§4.3.2: the server asks for a certificate, and §4.4.2.1 decides what a refusal costs" {
    // Three claims, and the middle one is the reason this exists: a
    // server that asks and then accepts silence has authenticated
    // nobody while looking like it did.
    const cases = [_]struct { require: bool, completes: bool }{
        .{ .require = true, .completes = false },
        .{ .require = false, .completes = true },
    };
    for (cases) |case| {
        var harness: Harness = undefined;
        try harness.initWith("http/1.1", .{ .require = case.require });
        defer harness.deinit();

        var client = Client.init(&client_x25519_private, &.{ .alpn = "http/1.1" });
        defer client.deinit();
        var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
        var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

        const hello = client.helloRecord(&client_out);
        const flight = try feedRecords(&harness.server, hello, &server_out);

        // The request really went out: our own client saw one and owes
        // an answer. Asserting on the client rather than on our encoder
        // is what makes this a wire check.
        const reply = try client.absorb(flight.send, &client_out);
        try testing.expectEqual(std.meta.activeTag(reply), .connected);
        try testing.expect(client.certificate_requested);

        // And the answer — an empty certificate_list — is judged by
        // `require` and nothing else.
        if (case.completes) {
            _ = try feedRecords(&harness.server, reply.connected, &server_out);
            try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
            // Completing is not the same as authenticating, and an
            // embedder that conflates them is why this field is public.
            try testing.expect(!harness.server.peer.verified);
        } else {
            try testing.expectError(
                error.CertificateRequired,
                feedRecords(&harness.server, reply.connected, &server_out),
            );
        }
    }
}

test "§4.3.2: no CertificateRequest unless the embedder asked for one" {
    // The default, and the one that must not regress: a server that was
    // never configured for mTLS sends nothing extra and our client never
    // sees a request.
    var harness: Harness = undefined;
    try harness.init("http/1.1");
    defer harness.deinit();

    var client = Client.init(&client_x25519_private, &.{ .alpn = "http/1.1" });
    defer client.deinit();
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    const hello = client.helloRecord(&client_out);
    const flight = try feedRecords(&harness.server, hello, &server_out);
    _ = try client.absorb(flight.send, &client_out);
    try testing.expect(!client.certificate_requested);
}

test "§4.4: one CertificateVerify per flight, and the count is not the peer's" {
    // `assert(messages_seen < 3)` in the server's flight loop assumed
    // Certificate, CertificateVerify, Finished. Nothing enforced the
    // middle one's uniqueness: each copy signs the transcript the last
    // one moved, so a client holding its own key can send any number,
    // and the fourth message reached the assertion as a panic.
    //
    // `.insecure_no_verification` is what makes this cheap to drive —
    // the checker records each message without looking at it — but the
    // count is peer-controlled under every policy.
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;

    var harness: Harness = undefined;
    try harness.initWith("http/1.1", .{
        .require = false,
        .policy = .insecure_no_verification,
    });
    defer harness.deinit();

    var client = Client.init(&client_x25519_private, &.{
        .alpn = "http/1.1",
        .certificate_verifies = 2,
    });
    defer client.deinit();

    const hello = client.helloRecord(&client_out);
    const flight = try feedRecords(&harness.server, hello, &server_out);
    const reply = try client.absorb(flight.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);

    // An error, not a panic — which is the whole distinction.
    try testing.expectError(
        error.UnexpectedMessage,
        feedRecords(&harness.server, reply.connected, &server_out),
    );
}
