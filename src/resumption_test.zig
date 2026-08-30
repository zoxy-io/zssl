//! Resumption (slice 3): the binder chain and PSK-mixed ladder pinned
//! against RFC 8448 §4, and ticket issuance → resumed session end to end,
//! with the client deriving every PSK from its own resumption_master —
//! agreement between the two derivations is the check.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const ClientHandshake = @import("ClientHandshake.zig");
const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const anti_replay = @import("anti_replay.zig");
const client_messages = @import("client_messages.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("record.zig");
const server_messages = @import("server_messages.zig");
const test_client = @import("test_client.zig");
const vectors = @import("rfc8448_vectors.zig");

const Client = test_client.TestClient(.aes_128_gcm_sha256);
const Schedule = key_schedule.KeySchedule(.aes_128_gcm_sha256);
const Sha256 = std.crypto.hash.sha2.Sha256;

const client_x25519_private = [_]u8{0x11} ** 31 ++ [_]u8{0x42};
const server_key_share_private = [_]u8{0x99} ** 47 ++ [_]u8{0x24};

test "§4 vectors: the binder chain, truncation arithmetic, and the PSK ladder" {
    // §3 ends where §4 begins: the resumed trace's PSK is §3's
    // resumption PSK, derived in slice 1's tests.
    try testing.expectEqualSlices(u8, &vectors.resumption_psk, &vectors.resumed_psk);

    var schedule = Schedule.initEarly(&vectors.resumed_psk);
    try testing.expectEqualSlices(u8, &vectors.resumed_early_secret, &schedule.secret);

    // §4.2.11.2's truncation: the ClientHello minus its binders section
    // (u16 list length + u8 binder length + 32 binder bytes here). The
    // trace prints the truncated form separately — our arithmetic must
    // land on exactly those bytes.
    const truncated = vectors.resumed_client_hello[0 .. vectors.resumed_client_hello.len - 35];
    try testing.expectEqualSlices(u8, &vectors.resumed_client_hello_truncated, truncated);
    var truncated_hash: [32]u8 = undefined;
    Sha256.hash(truncated, &truncated_hash, .{});
    try testing.expectEqualSlices(u8, &vectors.resumed_binder_hash, &truncated_hash);

    // The chain, step by step, then the one-call production path.
    var empty_hash: [32]u8 = undefined;
    Sha256.hash(&.{}, &empty_hash, .{});
    const binder_key = schedule.deriveAt(.early, "res binder", &empty_hash);
    try testing.expectEqualSlices(u8, &vectors.resumed_binder_key, &binder_key);
    const binder_finished_key = Schedule.finishedKey(&binder_key);
    try testing.expectEqualSlices(u8, &vectors.resumed_binder_finished_key, &binder_finished_key);
    const binder = Schedule.verifyData(&binder_finished_key, &truncated_hash);
    try testing.expectEqualSlices(u8, &vectors.resumed_binder_value, &binder);
    const one_call = schedule.pskBinder(.resumption, &truncated_hash);
    try testing.expectEqualSlices(u8, &vectors.resumed_binder_value, &one_call);
    // The binder also sits verbatim at the message's tail.
    try testing.expectEqualSlices(
        u8,
        vectors.resumed_client_hello[vectors.resumed_client_hello.len - 32 ..],
        &binder,
    );

    // The PSK-mixed ladder down to the master secret.
    var shared: [32]u8 = undefined;
    try backend.x25519Shared(&vectors.resumed_client_x25519_private, &vectors.resumed_server_x25519_public, &shared);
    try testing.expectEqualSlices(u8, &vectors.resumed_ecdhe_shared, &shared);
    var transcript: @import("transcript.zig").Transcript(Sha256) = .empty;
    transcript.update(&vectors.resumed_client_hello);
    transcript.update(&vectors.resumed_server_hello);
    schedule.advanceToHandshake(&shared);
    try testing.expectEqualSlices(u8, &vectors.resumed_handshake_secret, &schedule.secret);
    const hello_hash = transcript.currentHash();
    const client_traffic = schedule.deriveAt(.handshake, "c hs traffic", &hello_hash);
    const server_traffic = schedule.deriveAt(.handshake, "s hs traffic", &hello_hash);
    try testing.expectEqualSlices(u8, &vectors.resumed_client_hs_traffic_secret, &client_traffic);
    try testing.expectEqualSlices(u8, &vectors.resumed_server_hs_traffic_secret, &server_traffic);
    schedule.advanceToMaster();
    try testing.expectEqualSlices(u8, &vectors.resumed_master_secret, &schedule.secret);
}

test "the parser reads §4's real-world ClientHello, PSK offer included" {
    const hello = try client_hello.parse(&vectors.resumed_client_hello);
    try testing.expect(hello.supports_tls13);
    try testing.expect(hello.offersPskDheKe());
    const offer = (try client_hello.parsePskOffer(&hello)).?;
    try testing.expectEqual(@as(u8, 1), offer.count);
    try testing.expectEqual(@as(u16, 35), offer.binders_section_bytes);
    try testing.expectEqual(@as(usize, 178), offer.identities[0].len);
    try testing.expectEqualSlices(u8, &vectors.resumed_binder_value, offer.binders[0]);
}

/// The embedder's half of the seam, in miniature: an opaque-ticket → PSK
/// map standing in for zoxy's sealed tickets.
const TicketStore = struct {
    identities: [4][64]u8,
    identity_bytes: [4]u8,
    psks: [4][cipher_suite.hash_bytes_max]u8,
    count: u8,

    const empty: TicketStore = .{
        .identities = undefined,
        .identity_bytes = undefined,
        .psks = undefined,
        .count = 0,
    };

    fn add(store: *TicketStore, identity: []const u8, psk: []const u8) void {
        std.debug.assert(identity.len <= 64);
        std.debug.assert(store.count < 4);
        @memcpy(store.identities[store.count][0..identity.len], identity);
        store.identity_bytes[store.count] = @intCast(identity.len);
        @memset(&store.psks[store.count], 0);
        @memcpy(store.psks[store.count][0..psk.len], psk);
        store.count += 1;
    }

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age; // Age policy is the embedder's; this one has none.
        const store: *TicketStore = @ptrCast(@alignCast(context));
        var index: u8 = 0;
        while (index < store.count) : (index += 1) {
            std.debug.assert(index < 4);
            if (std.mem.eql(u8, store.identities[index][0..store.identity_bytes[index]], identity)) {
                psk_out.* = store.psks[index];
                return .{ .psk_bytes = 32, .kind = .resumption };
            }
        }
        return null;
    }
};

const Harness = struct {
    chain_storage: [Credentials.chain_bytes_max]u8,
    credentials: Credentials,
    reassembly: [8192]u8,
    flight: [Credentials.chain_bytes_max + 1024]u8,
    server: ServerHandshake,

    fn init(harness: *Harness, store: ?*TicketStore) !void {
        harness.credentials = try Credentials.load(
            @embedFile("testdata/cert.pem"),
            @embedFile("testdata/key.pem"),
            &harness.chain_storage,
            true,
        );
        harness.server = ServerHandshake.init(&.{
            .credentials = &harness.credentials,
            .server_random = .{0x5c} ** 32,
            .key_share_private = server_key_share_private,
            .reassembly = &harness.reassembly,
            .flight = &harness.flight,
            .psk_lookup = if (store) |context| .{
                .context = context,
                .lookup = TicketStore.lookup,
            } else null,
        });
    }

    /// Same server, but with the `psk_lookup` handed in whole. `init`
    /// takes a `TicketStore` because most tests want one; an external
    /// PSK answers through a different embedder entirely, which is the
    /// point of the seam being a function pointer and a context.
    fn initLookup(harness: *Harness, lookup: ServerHandshake.PskLookup) !void {
        harness.credentials = try Credentials.load(
            @embedFile("testdata/cert.pem"),
            @embedFile("testdata/key.pem"),
            &harness.chain_storage,
            true,
        );
        harness.server = ServerHandshake.init(&.{
            .credentials = &harness.credentials,
            .server_random = .{0x5c} ** 32,
            .key_share_private = server_key_share_private,
            .reassembly = &harness.reassembly,
            .flight = &harness.flight,
            .psk_lookup = lookup,
        });
    }

    fn deinit(harness: *Harness) void {
        harness.server.deinit();
        harness.credentials.deinit();
    }
};

fn completeHandshake(server: *ServerHandshake, client: *Client) !void {
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    const hello = client.helloRecord(&client_out);
    const flight = (try server.handleRecord(hello, &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    const reply = try client.absorb(flight.send, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);
    var index: usize = 0;
    var final: ?ServerHandshake.Event = null;
    var count: u8 = 0;
    while (index < reply.connected.len) : (count += 1) {
        try testing.expect(count < 8);
        const length = std.mem.readInt(u16, reply.connected[index + 3 ..][0..2], .big);
        const one = reply.connected[index..][0 .. record.header_bytes + length];
        if (try server.handleRecord(one, &server_out)) |event| final = event;
        index += one.len;
    }
    try testing.expectEqual(std.meta.activeTag(final.?), .connected);
}

test "§4 vectors: the 0-RTT branch of the schedule, down to the record keys" {
    // The early secret has two children and this tree only ever grew
    // one of them. `client_early_traffic_secret` is the other, and it is
    // derivable the moment the ClientHello exists — which is the whole
    // reason 0-RTT can put application data on the wire before a
    // ServerHello answers.
    //
    // No production code was needed for this: `deriveAt` and
    // `trafficKeys` already spell it. That is worth pinning *before*
    // anything is built on top, because a schedule that agrees with the
    // RFC here is one the accept path can be debugged against.
    var schedule = Schedule.initEarly(&vectors.resumed_psk);
    defer schedule.wipe();
    try testing.expectEqualSlices(u8, &vectors.resumed_early_secret, &schedule.secret);

    // The transcript is the ClientHello and nothing else. Checked
    // against the message rather than taken from the trace's label, so
    // the vector is tied to bytes we also parse elsewhere.
    var hello_hash: [32]u8 = undefined;
    Sha256.hash(&vectors.resumed_client_hello, &hello_hash, .{});
    try testing.expectEqualSlices(u8, &vectors.resumed_client_hello_hash, &hello_hash);

    const early_traffic = schedule.deriveAt(.early, "c e traffic", &hello_hash);
    try testing.expectEqualSlices(
        u8,
        &vectors.resumed_client_early_traffic_secret,
        &early_traffic,
    );

    // And the record keys the client protects early data with.
    const keys = Schedule.trafficKeys(&early_traffic);
    try testing.expectEqualSlices(u8, &vectors.resumed_client_early_key, &keys.key);
    try testing.expectEqualSlices(u8, &vectors.resumed_client_early_iv, &keys.iv);
}

test "resumption end to end: tickets out, PSK session up, no certificate" {
    var store: TicketStore = .empty;

    // Session one: a full handshake, then two tickets.
    var first: Harness = undefined;
    try first.init(null);
    defer first.deinit();
    var client_one = Client.init(&client_x25519_private, &.{});
    defer client_one.deinit();
    try completeHandshake(&first.server, &client_one);
    try testing.expect(!first.server.resumed);

    var ticket_out: [record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    const nonces = [2][1]u8{ .{0x00}, .{0x01} };
    const identities = [2][]const u8{ "sealed-ticket-zero", "sealed-ticket-one" };
    for (nonces, identities) |nonce, identity| {
        // The zoxy ordering: the PSK is derived before the ticket that
        // will stand for it exists, then sealed (faked here by the map).
        var psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
        const psk = first.server.resumptionPsk(&nonce, &psk_buffer);
        store.add(identity, psk);
        const sealed = try first.server.sendNewSessionTicket(&.{
            .lifetime_s = 3600,
            .age_add = 0xdeadbeef,
            .ticket_nonce = &nonce,
            .ticket = identity,
        }, &ticket_out);
        const event = try client_one.absorb(sealed, &client_out);
        try testing.expectEqual(std.meta.activeTag(event), .none);
    }
    try testing.expectEqual(@as(u8, 2), client_one.ticket_count);
    // The client derived each PSK from its own resumption_master; the
    // server derived its copies from its own. They must be one value.
    try testing.expectEqualSlices(u8, store.psks[0][0..32], client_one.tickets[0].psk[0..32]);
    try testing.expectEqualSlices(u8, store.psks[1][0..32], client_one.tickets[1].psk[0..32]);

    // Session two: resume with the first ticket.
    var second: Harness = undefined;
    try second.init(&store);
    defer second.deinit();
    var client_two = Client.init(&client_x25519_private, &.{
        .resume_with = &client_one.tickets[0],
    });
    defer client_two.deinit();
    try completeHandshake(&second.server, &client_two);
    try testing.expect(second.server.resumed);
    try testing.expect(client_two.psk_accepted);
    // A PSK authenticates the session: no certificate crossed the wire.
    try testing.expect(!client_two.certificate_verified);

    // The resumed session works and can mint tickets of its own.
    var server_out: [record.wire_record_bytes_max]u8 = undefined;
    const ping = try client_two.sendApplicationData("ping", &client_out);
    const ping_event = (try second.server.handleRecord(ping, &server_out)).?;
    try testing.expectEqualSlices(u8, "ping", ping_event.application_data);
    var psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const chained_psk = second.server.resumptionPsk(&.{0x02}, &psk_buffer);
    try testing.expectEqual(@as(usize, 32), chained_psk.len);
    const chained = try second.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 1,
        .ticket_nonce = &.{0x02},
        .ticket = "sealed-ticket-chained",
    }, &ticket_out);
    const chained_event = try client_two.absorb(chained, &client_out);
    try testing.expectEqual(std.meta.activeTag(chained_event), .none);
    try testing.expectEqual(@as(u8, 1), client_two.ticket_count);
}

test "§4.4.1: the server verifies a binder on a retry ClientHello" {
    // The other end of the same surgery. A PSK offered on CH2 is bound
    // to message_hash(CH1), the HelloRetryRequest, and then the
    // truncated CH2 — so a server that hashes the truncation alone
    // refuses every legitimate resumption across a retry, and one that
    // hashes anything else accepts binders it should not.
    //
    // The transcript is rebuilt here with `std.crypto` from the bytes
    // that actually crossed, so the check is agreement between two
    // derivations rather than `Transcript.hashWith` against itself.
    const psk = [_]u8{0x9a} ** 32;
    const random = [_]u8{0x07} ** 32;
    const unusable_group: u16 = 0xfefe; // Parsed, skipped, no share we can use.

    // CH1 offers the identity and a share for a group we do not hold,
    // which is §4.2.8's legal way to ask the server to choose — and the
    // only way to make this server retry at all, since it takes any of
    // the three groups it knows.
    var ch1_storage: [client_messages.hello_bytes_max]u8 = undefined;
    const ch1 = client_messages.clientHello(&ch1_storage, &.{
        .random = &random,
        .session_id = &.{},
        .share_group = unusable_group,
        .share_public = &(.{0xab} ** 32),
        .groups = &.{client_hello.group_secp256r1},
        .psk = .{ .identity = "ticket", .obfuscated_age = 0, .binder_bytes = 32 },
    });
    client_messages.patchBinder(ch1_storage[0..ch1.len], &psk, null);
    var ch1_record: [record.wire_record_bytes_max]u8 = undefined;
    const ch1_framed = frameHandshake(&ch1_record, ch1_storage[0..ch1.len]);

    // The share CH2 answers the demand with.
    var share_storage: [backend.group_public_bytes_max]u8 = undefined;
    const share = try backend.keySharePublic(
        .secp256r1,
        &(.{0x71} ** 32),
        &share_storage,
    );

    // Three shapes of second hello. The first is the legitimate one.
    // The second carries the binder CH1's own truncation would produce —
    // the regression guard, since a server that skipped §4.4.1's surgery
    // is exactly the server that accepts it. The third drops the offer
    // altogether, which §4.1.2 does not list among the changes a second
    // ClientHello may make.
    const Second = enum { reconstructed, truncation_only, omitted };
    for ([_]Second{ .reconstructed, .truncation_only, .omitted }) |shape| {
        var store: TicketStore = .empty;
        store.add("ticket", &psk);
        var harness: Harness = undefined;
        try harness.init(&store);
        defer harness.deinit();
        var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;

        const retry = (try harness.server.handleRecord(ch1_framed, &server_out)).?;
        try testing.expectEqual(std.meta.activeTag(retry), .send);
        try testing.expectEqual(
            ServerHandshake.State.awaiting_retry_client_hello,
            harness.server.state,
        );
        // The flight is the HelloRetryRequest and then §D.4's CCS.
        const hrr_length = std.mem.readInt(u16, retry.send[3..5], .big);
        const hrr = retry.send[record.header_bytes..][0..hrr_length];

        var ch2_storage: [client_messages.hello_bytes_max]u8 = undefined;
        const ch2 = client_messages.clientHello(&ch2_storage, &.{
            .random = &random,
            .session_id = &.{},
            .share_group = client_hello.group_secp256r1,
            .share_public = share,
            .groups = &.{client_hello.group_secp256r1},
            .psk = if (shape == .omitted)
                null
            else
                .{ .identity = "ticket", .obfuscated_age = 0, .binder_bytes = 32 },
        });
        const ch2_bytes = ch2_storage[0..ch2.len];
        var ch2_record: [record.wire_record_bytes_max]u8 = undefined;
        if (shape == .omitted) {
            try testing.expectError(
                error.MissingExtension,
                harness.server.handleRecord(frameHandshake(&ch2_record, ch2_bytes), &server_out),
            );
            continue;
        }

        // The synthetic message_hash message — type 254, a u24 length,
        // the hash of CH1 — then the retry, then the truncated CH2.
        var ch1_hash: [32]u8 = undefined;
        Sha256.hash(ch1_storage[0..ch1.len], &ch1_hash, .{});
        var surgery = Sha256.init(.{});
        surgery.update(&[_]u8{ 254, 0, 0, 32 });
        surgery.update(&ch1_hash);
        surgery.update(hrr);
        surgery.update(client_messages.binderTruncation(ch2_bytes, 32));
        var digest: [32]u8 = undefined;
        surgery.final(&digest);
        client_messages.patchBinder(
            ch2_bytes,
            &psk,
            if (shape == .reconstructed) &digest else null,
        );

        const ch2_framed = frameHandshake(&ch2_record, ch2_bytes);
        if (shape == .truncation_only) {
            // §4.2.11: an identity the embedder recognized whose binder
            // does not verify is a refusal, never a downgrade to a full
            // handshake.
            try testing.expectError(
                error.DecryptError,
                harness.server.handleRecord(ch2_framed, &server_out),
            );
            continue;
        }
        const flight = (try harness.server.handleRecord(ch2_framed, &server_out)).?;
        try testing.expectEqual(std.meta.activeTag(flight), .send);
        try testing.expect(harness.server.resumed);
        try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);
    }
}

/// Wrap one handshake message in its record, ready to feed.
fn frameHandshake(out: []u8, message: []const u8) []const u8 {
    assert(out.len >= record.header_bytes + message.len);
    record.writeHeader(
        .{ .content_type = .handshake, .length = @intCast(message.len) },
        out[0..record.header_bytes],
    );
    @memcpy(out[record.header_bytes..][0..message.len], message);
    return out[0 .. record.header_bytes + message.len];
}

/// A `psk_lookup` that answers one out-of-band identity, and answers it
/// as `.external` so §4.2.11.2's "ext binder" label is the one derived.
/// Deliberately shorter than a hash: §4.2.11 associates a hash with an
/// external PSK and says nothing about the key's length, and the length
/// is the part a resumption-only implementation quietly assumes.
const ExternalStore = struct {
    const identity = "out-of-band-identity";
    const secret = [_]u8{0x5a} ** 16;

    fn lookup(
        context: *anyopaque,
        offered: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = context;
        _ = obfuscated_age; // An external PSK has no ticket age to police.
        if (!std.mem.eql(u8, offered, identity)) return null;
        @memcpy(psk_out[0..secret.len], &secret);
        return .{ .psk_bytes = secret.len, .kind = .external };
    }
};

test "§4.2.11.2: an external PSK is accepted under the ext binder label" {
    var context: u8 = 0;
    var harness: Harness = undefined;
    try harness.initLookup(.{ .context = &context, .lookup = ExternalStore.lookup });
    defer harness.deinit();

    var offer: test_client.Ticket = .{
        .lifetime_s = 0,
        .age_add = 0,
        .nonce = undefined,
        .nonce_bytes = 0,
        .ticket = undefined,
        .ticket_bytes = ExternalStore.identity.len,
        .psk = undefined,
        .psk_bytes = ExternalStore.secret.len,
        .kind = .external,
    };
    @memcpy(offer.ticket[0..ExternalStore.identity.len], ExternalStore.identity);
    @memcpy(offer.psk[0..ExternalStore.secret.len], &ExternalStore.secret);

    var client = Client.init(&client_x25519_private, &.{ .resume_with = &offer });
    defer client.deinit();
    try completeHandshake(&harness.server, &client);

    // The session came up on the PSK: no certificate, and the server
    // says it resumed even though no ticket was ever issued — from
    // §4.2.11's side the two are the same handshake.
    try testing.expect(harness.server.resumed);
    try testing.expect(client.psk_accepted);
    try testing.expect(!client.certificate_verified);

    // And it carries traffic, which is what says the two sides agreed on
    // an early secret derived from a 16-byte PSK.
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [record.wire_record_bytes_max]u8 = undefined;
    const ping = try client.sendApplicationData("external", &client_out);
    const event = (try harness.server.handleRecord(ping, &server_out)).?;
    try testing.expectEqualSlices(u8, "external", event.application_data);
}

test "an external PSK offered under the resumption label is refused" {
    var context: u8 = 0;
    var harness: Harness = undefined;
    try harness.initLookup(.{ .context = &context, .lookup = ExternalStore.lookup });
    defer harness.deinit();

    // Same identity, same secret, wrong label. §4.2.11.2 makes the label
    // part of the computation, so this is a binder that does not verify
    // — and the alert says so rather than saying "unknown identity",
    // because the identity *was* ours.
    var offer: test_client.Ticket = .{
        .lifetime_s = 0,
        .age_add = 0,
        .nonce = undefined,
        .nonce_bytes = 0,
        .ticket = undefined,
        .ticket_bytes = ExternalStore.identity.len,
        .psk = undefined,
        .psk_bytes = ExternalStore.secret.len,
        .kind = .resumption,
    };
    @memcpy(offer.ticket[0..ExternalStore.identity.len], ExternalStore.identity);
    @memcpy(offer.psk[0..ExternalStore.secret.len], &ExternalStore.secret);

    var client = Client.init(&client_x25519_private, &.{ .resume_with = &offer });
    defer client.deinit();
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    const hello = client.helloRecord(&client_out);
    try testing.expectError(
        error.DecryptError,
        harness.server.handleRecord(hello, &server_out),
    );
}

test "resumption failure paths: bad binder is fatal, unknown ticket falls back" {
    var store: TicketStore = .empty;
    var seed: Harness = undefined;
    try seed.init(null);
    defer seed.deinit();
    var client_seed = Client.init(&client_x25519_private, &.{});
    defer client_seed.deinit();
    try completeHandshake(&seed.server, &client_seed);
    var psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    var ticket_out: [record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    const psk = seed.server.resumptionPsk(&.{0x00}, &psk_buffer);
    store.add("sealed-ticket-zero", psk);
    const sealed = try seed.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 0,
        .ticket_nonce = &.{0x00},
        .ticket = "sealed-ticket-zero",
    }, &ticket_out);
    _ = try client_seed.absorb(sealed, &client_out);

    // A recognized identity with a corrupted binder MUST abort (§4.2.11).
    {
        var harness: Harness = undefined;
        try harness.init(&store);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{
            .resume_with = &client_seed.tickets[0],
            .corrupt_binder = true,
        });
        defer client.deinit();
        var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
        const hello = client.helloRecord(&client_out);
        try testing.expectError(error.DecryptError, harness.server.handleRecord(hello, &server_out));
        try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
    }

    // An identity nobody recognizes is not an attack, it is a stale
    // ticket: full handshake, certificate and all.
    {
        var empty_store: TicketStore = .empty;
        var harness: Harness = undefined;
        try harness.init(&empty_store);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{
            .resume_with = &client_seed.tickets[0],
        });
        defer client.deinit();
        try completeHandshake(&harness.server, &client);
        try testing.expect(!harness.server.resumed);
        try testing.expect(!client.psk_accepted);
        try testing.expect(client.certificate_verified);
    }

    // Offering PSK without psk_dhe_ke: the offer is ignored (§4.2.9).
    {
        var harness: Harness = undefined;
        try harness.init(&store);
        defer harness.deinit();
        var client = Client.init(&client_x25519_private, &.{
            .resume_with = &client_seed.tickets[0],
            .psk_mode_byte = 0x00,
        });
        defer client.deinit();
        try completeHandshake(&harness.server, &client);
        try testing.expect(!harness.server.resumed);
        try testing.expect(client.certificate_verified);
    }
}

test "§4.6.1: a ticket is not used beyond its lifetime" {
    const Issued = ServerHandshake.Issued;
    const hour_ms: u64 = 60 * 60 * 1000;
    const issued: Issued = .{ .at_ms = 1000 * hour_ms, .lifetime_s = 3600 };

    // The boundary, both sides of it. Exactly at the lifetime is still
    // inside it — §4.6.1 gives a duration, and a ticket is good for it.
    try testing.expect(!issued.expired(issued.at_ms));
    try testing.expect(!issued.expired(issued.at_ms + hour_ms));
    try testing.expect(issued.expired(issued.at_ms + hour_ms + 1));

    // A clock that ran backwards, or an `at_ms` in the future, is the
    // embedder's fault and not the peer's. Saturating to "no age at all"
    // answers fresh, which is the wrong half of the choice to make
    // silently — so the arithmetic is pinned here rather than left to a
    // reader to re-derive.
    try testing.expect(!issued.expired(0));
    try testing.expect(!issued.expired(issued.at_ms - hour_ms));

    // §4.6.1 caps `ticket_lifetime` at a week. A lookup answering more
    // is describing a ticket that should never have been minted, and the
    // cap is applied rather than believed.
    const overlong: Issued = .{ .at_ms = 0, .lifetime_s = std.math.maxInt(u32) };
    try testing.expect(!overlong.expired(Issued.lifetime_s_max * 1000));
    try testing.expect(overlong.expired(@as(u64, Issued.lifetime_s_max) * 1000 + 1));
}

/// A `psk_lookup` answering one identity with an issuance the test
/// chooses, so §4.6.1's lifetime can be walked from either side.
const ExpiringStore = struct {
    psk: [cipher_suite.hash_bytes_max]u8,
    issued: ServerHandshake.Issued,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age;
        const store: *ExpiringStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, identity, "ticket")) return null;
        psk_out.* = store.psk;
        return .{ .psk_bytes = 32, .kind = .resumption, .issued = store.issued };
    }
};

test "§4.6.1: an expired ticket falls back to a full handshake, not an error" {
    // The lookup still recognises the identity — this is our own policy
    // declining, not a peer misbehaving — so the right answer is the
    // handshake the client would have got with no ticket at all. A
    // refusal here would turn every expired resumption into a failed
    // connection.
    const psk = [_]u8{0x9a} ** 32;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    const hour_ms: u64 = 60 * 60 * 1000;

    for ([_]bool{ false, true }) |expired| {
        var store: ExpiringStore = .{
            .psk = undefined,
            .issued = .{ .at_ms = 1000 * hour_ms, .lifetime_s = 3600 },
        };
        @memset(&store.psk, 0);
        @memcpy(store.psk[0..psk.len], &psk);
        var harness: Harness = undefined;
        try harness.initLookup(.{ .context = &store, .lookup = ExpiringStore.lookup });
        defer harness.deinit();
        harness.server.config.now_ms = store.issued.at_ms +
            if (expired) hour_ms + 1 else hour_ms;

        var ticket: test_client.Ticket = .{
            .lifetime_s = 3600,
            .age_add = 0,
            .nonce = undefined,
            .nonce_bytes = 1,
            .ticket = undefined,
            .ticket_bytes = 6,
            .psk = undefined,
            .psk_bytes = 32,
            .kind = .resumption,
        };
        @memset(&ticket.psk, 0);
        @memcpy(ticket.psk[0..psk.len], &psk);
        @memcpy(ticket.ticket[0..6], "ticket");

        var client = Client.init(&client_x25519_private, &.{ .resume_with = &ticket });
        defer client.deinit();
        const flight = (try harness.server.handleRecord(
            client.helloRecord(&client_out),
            &server_out,
        )).?;
        try testing.expectEqual(std.meta.activeTag(flight), .send);
        // Fresh resumes on the PSK; expired signs a certificate instead.
        try testing.expectEqual(!expired, harness.server.resumed);
    }
}

/// A `psk_lookup` that answers one ticket on 0-RTT terms the test picks.
const EarlyDataStore = struct {
    psk: [cipher_suite.hash_bytes_max]u8,
    issued: ServerHandshake.Issued,
    early_data: ?ServerHandshake.EarlyData,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age;
        const store: *EarlyDataStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, identity, "ticket")) return null;
        psk_out.* = store.psk;
        return .{
            .psk_bytes = 32,
            .kind = .resumption,
            .issued = store.issued,
            .early_data = store.early_data,
        };
    }
};

const EarlyDataFixture = struct {
    const psk = [_]u8{0x7e} ** 32;
    const issued_at_ms: u64 = 4_000_000;
    const age_add: u32 = 0x0bad_c0de;
    /// The client learned the ticket 250 ms ago and we are 250 ms past
    /// issuing it: no skew, which §8.3 wants.
    const now_ms: u64 = issued_at_ms + 250;

    fn ticket() test_client.Ticket {
        var entry: test_client.Ticket = .{
            .lifetime_s = 3600,
            .age_add = age_add,
            .nonce = undefined,
            .nonce_bytes = 1,
            .ticket = undefined,
            .ticket_bytes = 6,
            .psk = undefined,
            .psk_bytes = 32,
            .kind = .resumption,
        };
        @memset(&entry.psk, 0);
        @memcpy(entry.psk[0..psk.len], &psk);
        @memcpy(entry.ticket[0..6], "ticket");
        return entry;
    }

    fn store(bytes_max: u32, suite: cipher_suite.CipherSuite) EarlyDataStore {
        var s: EarlyDataStore = .{
            .psk = undefined,
            .issued = .{ .at_ms = issued_at_ms, .age_add = age_add, .lifetime_s = 3600 },
            .early_data = .{ .bytes_max = bytes_max, .suite = suite },
        };
        @memset(&s.psk, 0);
        @memcpy(s.psk[0..psk.len], &psk);
        return s;
    }
};

test "§4.2.10 end to end: early data is accepted, read, and the session completes" {
    // The property slice 2's unit tests could not reach: a real client
    // puts application data on the wire before the server has said
    // anything, and the server reads it under keys derived from the
    // hello alone — then the same handshake finishes normally with the
    // client's Finished MACing a transcript that includes §4.5's
    // EndOfEarlyData and application secrets that do not (§4.4 vs §7.1).
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var early_out: [record.wire_record_bytes_max]u8 = undefined;

    var registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var register: anti_replay.StrikeRegister = .{ .entries = &registry };
    var store = EarlyDataFixture.store(1024, .aes_128_gcm_sha256);
    var harness: Harness = undefined;
    try harness.initLookup(.{ .context = &store, .lookup = EarlyDataStore.lookup });
    defer harness.deinit();
    harness.server.config.now_ms = EarlyDataFixture.now_ms;
    harness.server.config.strike_register = &register;

    var ticket = EarlyDataFixture.ticket();
    var client = Client.init(&client_x25519_private, &.{
        .resume_with = &ticket,
        .offer_early_data = true,
    });
    defer client.deinit();

    // The hello, then 0-RTT data behind it — before the server has been
    // fed anything at all, which is the whole point of the mode.
    const hello = client.helloRecord(&client_out);
    const early = try client.earlyDataRecord("GET /0rtt", &early_out);

    const flight = (try harness.server.handleRecord(hello, &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    try testing.expect(harness.server.early_data_accepted);
    try testing.expect(harness.server.resumed);
    try testing.expectEqual(
        ServerHandshake.State.awaiting_end_of_early_data,
        harness.server.state,
    );

    // Read, not discarded.
    var flight_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
    @memcpy(flight_storage[0..flight.send.len], flight.send);
    const flight_bytes = flight_storage[0..flight.send.len];
    const early_event = (try harness.server.handleRecord(early, &server_out)).?;
    try testing.expectEqualSlices(u8, "GET /0rtt", early_event.application_data);
    try testing.expectEqual(@as(u32, 9), harness.server.early_data_bytes);

    // The client's flight carries EndOfEarlyData and then its Finished,
    // and the server completes on it — which only works if both ends
    // agree about which transcript the Finished covers.
    const reply = try client.absorb(flight_bytes, &client_out);
    try testing.expectEqual(std.meta.activeTag(reply), .connected);
    var final: ?ServerHandshake.Event = null;
    var index: usize = 0;
    var count: u8 = 0;
    while (index < reply.connected.len) : (count += 1) {
        try testing.expect(count < 8);
        const length = std.mem.readInt(u16, reply.connected[index + 3 ..][0..2], .big);
        const one = reply.connected[index..][0 .. record.header_bytes + length];
        if (try harness.server.handleRecord(one, &server_out)) |event| final = event;
        index += one.len;
    }
    try testing.expectEqual(std.meta.activeTag(final.?), .connected);
    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
}

/// Drive one hello at a fresh server on the given terms, and answer
/// whether the early data behind it was accepted. Everything the test
/// wants to vary is a parameter; everything else is the fixture, so a
/// refusal can only come from the thing under test.
fn earlyDataAccepted(options: struct {
    now_ms: u64 = EarlyDataFixture.now_ms,
    bytes_max: u32 = 1024,
    /// §4.2.10 requires the ticket's suite to be the negotiated one.
    /// The fixture negotiates AES-128-GCM, so anything else here is a
    /// mismatch and nothing else about the hello changes.
    suite: cipher_suite.CipherSuite = .aes_128_gcm_sha256,
    register: ?*anti_replay.StrikeRegister,
    clock: bool = true,
    terms: bool = true,
    /// Offer an identity the server does not know ahead of the real
    /// one, so the PSK it selects is not the first offered.
    decoy_first: bool = false,
}) !bool {
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var store = EarlyDataFixture.store(options.bytes_max, options.suite);
    if (!options.terms) store.early_data = null;
    var harness: Harness = undefined;
    try harness.initLookup(.{ .context = &store, .lookup = EarlyDataStore.lookup });
    defer harness.deinit();
    if (options.clock) harness.server.config.now_ms = options.now_ms;
    harness.server.config.strike_register = options.register;

    var ticket = EarlyDataFixture.ticket();
    var client = Client.init(&client_x25519_private, &.{
        .resume_with = &ticket,
        .offer_early_data = true,
        .psk_decoy_first = options.decoy_first,
    });
    defer client.deinit();
    const flight = (try harness.server.handleRecord(
        client.helloRecord(&client_out),
        &server_out,
    )).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    // Whatever the answer, the handshake itself survives: refusing 0-RTT
    // costs a round trip and never the connection.
    try testing.expect(harness.server.resumed);
    return harness.server.early_data_accepted;
}

test "§8: every gate on early data refuses on its own, and none of them fails the handshake" {
    // The client's hello is byte-identical across all of these — the
    // randoms and the scalar are fixtures — so the same hello is
    // accepted or refused purely on the server's terms. That is what
    // makes each row a test of one gate.
    var registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var register: anti_replay.StrikeRegister = .{ .entries = &registry };

    // The control: everything present, and it is accepted.
    try testing.expect(try earlyDataAccepted(.{ .register = &register }));

    // §8.2, and the reason the register exists: the *same* hello again,
    // at the same instant, against a server that shares the register.
    // Byte-for-byte replay is what an attacker who captured the first
    // one has, and it must not be read twice.
    try testing.expect(!try earlyDataAccepted(.{ .register = &register }));

    // §8.3: the same hello arriving an hour after the ticket was issued
    // claims an age that no longer matches the one we measure. A fresh
    // register, so this is the freshness check refusing and not §8.2.
    var stale_registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var stale_register: anti_replay.StrikeRegister = .{ .entries = &stale_registry };
    try testing.expect(!try earlyDataAccepted(.{
        .register = &stale_register,
        .now_ms = EarlyDataFixture.issued_at_ms + 60 * 60 * 1000,
    }));

    // The three opt-ins, each absent in turn. A server that never
    // thought about any one of them does not accept early data, which is
    // the whole reason they default to off rather than on.
    var spare_registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var spare: anti_replay.StrikeRegister = .{ .entries = &spare_registry };
    try testing.expect(!try earlyDataAccepted(.{ .register = null }));
    try testing.expect(!try earlyDataAccepted(.{ .register = &spare, .clock = false }));
    try testing.expect(!try earlyDataAccepted(.{ .register = &spare, .terms = false }));
    // And a ticket whose advertised limit is zero permits nothing,
    // which is a server saying "resume, but not before I answer".
    try testing.expect(!try earlyDataAccepted(.{ .register = &spare, .bytes_max = 0 }));

    // §4.2.10: "the server MUST ... only accept early data if the PSK
    // selected is the first one offered". An unknown identity ahead of
    // the real one still resumes — a server walks past what it does not
    // recognise — but the selection is no longer the first, and the
    // early data behind it is not ours to read.
    var decoy_registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var decoy_register: anti_replay.StrikeRegister = .{ .entries = &decoy_registry };
    try testing.expect(!try earlyDataAccepted(.{
        .register = &decoy_register,
        .decoy_first = true,
    }));

    // §4.2.10 again: the suite must be the one the ticket was issued
    // under. AES-256-GCM hashes to SHA-384 and this PSK is 32 bytes, so
    // the mismatch is visible only because the ticket carries its suite
    // — inferring it from the PSK's length would miss the case that
    // matters, two suites sharing one hash.
    var suite_registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var suite_register: anti_replay.StrikeRegister = .{ .entries = &suite_registry };
    try testing.expect(!try earlyDataAccepted(.{
        .register = &suite_register,
        .suite = .chacha20_poly1305_sha256,
    }));
}

test "§4.6.1: early data past the ticket's own limit ends the connection" {
    // `max_early_data_size` is a number the client was given and sized
    // its send against, so a client past it is not one we issued that
    // ticket to. Distinct from the skip ceiling, which bounds data we
    // declined and never keyed.
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var early_out: [record.wire_record_bytes_max]u8 = undefined;
    var registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var register: anti_replay.StrikeRegister = .{ .entries = &registry };
    var store = EarlyDataFixture.store(8, .aes_128_gcm_sha256);
    var harness: Harness = undefined;
    try harness.initLookup(.{ .context = &store, .lookup = EarlyDataStore.lookup });
    defer harness.deinit();
    harness.server.config.now_ms = EarlyDataFixture.now_ms;
    harness.server.config.strike_register = &register;

    var ticket = EarlyDataFixture.ticket();
    var client = Client.init(&client_x25519_private, &.{
        .resume_with = &ticket,
        .offer_early_data = true,
    });
    defer client.deinit();
    const hello = client.helloRecord(&client_out);
    const first = try client.earlyDataRecord("12345678", &early_out);
    var second_out: [record.wire_record_bytes_max]u8 = undefined;
    const second = try client.earlyDataRecord("9", &second_out);

    _ = (try harness.server.handleRecord(hello, &server_out)).?;
    try testing.expect(harness.server.early_data_accepted);
    // Exactly the limit is inside it.
    const event = (try harness.server.handleRecord(first, &server_out)).?;
    try testing.expectEqualSlices(u8, "12345678", event.application_data);
    try testing.expectEqual(@as(u32, 8), harness.server.early_data_bytes);
    // One byte past is not.
    try testing.expectError(
        error.TooMuchEarlyData,
        harness.server.handleRecord(second, &server_out),
    );
}

test "§4.6.1: a ticket advertises how much early data it permits" {
    // The other half of accepting 0-RTT, and the half a server cannot
    // skip: a client offers early data only against a ticket that told
    // it how much it may send. A server that accepts and never
    // advertises is one no client ever takes up on it.
    var buffers_out: [record.wire_record_bytes_max]u8 = undefined;
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var store: TicketStore = .empty;
    var harness: Harness = undefined;
    try harness.init(&store);
    defer harness.deinit();
    var client = Client.init(&client_x25519_private, &.{});
    defer client.deinit();
    try completeHandshake(&harness.server, &client);

    const sealed = try harness.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 0x1234,
        .ticket_nonce = &.{0x01},
        .ticket = "sealed",
        .early_data_bytes_max = 16384,
    }, &buffers_out);

    // The harness client round-trips the bytes. It skips the extension
    // block wholesale rather than parsing it, so this shows the message
    // framing survives and nothing more — the production client is what
    // proves finding 7's rule here, and `client_server_test`'s
    // `issueTicket` is where it meets this extension.
    const event = try client.absorb(sealed, &client_out);
    try testing.expectEqual(std.meta.activeTag(event), .none);
    try testing.expectEqual(@as(u8, 1), client.ticket_count);

    // And the same ticket without one, which is every ticket this
    // library issued before now.
    const plain = try harness.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 0x1234,
        .ticket_nonce = &.{0x02},
        .ticket = "sealed2",
    }, &server_out);
    const second = try client.absorb(plain, &client_out);
    try testing.expectEqual(std.meta.activeTag(second), .none);
    try testing.expectEqual(@as(u8, 2), client.ticket_count);

    // The bytes themselves, off the builder rather than the record —
    // what went out above is sealed, and the shape is the point: type
    // 42, a u16 length of 4, then the u32 §4.6.1 puts there.
    var message_out: [256]u8 = undefined;
    const advertised = server_messages.newSessionTicket(
        &message_out,
        3600,
        0x1234,
        &.{0x01},
        "sealed",
        16384,
    );
    const wanted = [_]u8{ 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x40, 0x00 };
    try testing.expect(std.mem.indexOf(u8, advertised, &wanted) != null);
    const silent = server_messages.newSessionTicket(
        &message_out,
        3600,
        0x1234,
        &.{0x01},
        "sealed",
        null,
    );
    try testing.expect(std.mem.indexOf(u8, silent, &wanted) == null);
    // Silence is an empty block, not an absent one: §4.6.1 makes
    // `extensions` mandatory and a client reads it either way.
    try testing.expectEqual(advertised.len - 8, silent.len);
}

test "§4.6.1: the largest legal ticket still fits with 0-RTT advertised" {
    // `new_session_ticket_bytes_max` is not a guess, it is the entire
    // safety net: `wire.Builder` bounds-checks nothing, so every write
    // is an assertion against a buffer this constant sized. Advertising
    // early data grew the worst case by eight bytes and the constant
    // did not move with it — a legal maximum-size ticket would have run
    // off the end of the buffer `sendNewSessionTicket` allocates.
    var message_out: [server_messages.new_session_ticket_bytes_max]u8 = undefined;
    const nonce = [_]u8{0x5a} ** 255;
    const ticket = [_]u8{0xa5} ** server_messages.ticket_bytes_max;
    const largest = server_messages.newSessionTicket(
        &message_out,
        server_messages.ticket_lifetime_s_max,
        0xffff_ffff,
        &nonce,
        &ticket,
        std.math.maxInt(u32),
    );
    try testing.expectEqual(@as(usize, server_messages.new_session_ticket_bytes_max), largest.len);
    // And the declared length agrees with what was written, which is
    // the property an over-run would break first.
    const declared = std.mem.readInt(u24, largest[1..4], .big);
    try testing.expectEqual(largest.len - 4, declared);
}

test "§4.2.10 end to end: our client offers 0-RTT and our server takes it" {
    // Both production machines, both directions of the same feature.
    // Every earlier test drove one side against bytes the test built;
    // this is the client deriving `c e traffic` from a ticket it was
    // issued, and the server deriving the same secret from the hello it
    // received — agreement between two independent derivations, which
    // is what the RFC 8448 vectors cannot show because they check one.
    var client_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var server_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var early_out: [record.wire_record_bytes_max]u8 = undefined;

    var registry: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var register: anti_replay.StrikeRegister = .{ .entries = &registry };
    var store = EarlyDataFixture.store(1024, .aes_128_gcm_sha256);
    var harness: Harness = undefined;
    try harness.initLookup(.{ .context = &store, .lookup = EarlyDataStore.lookup });
    defer harness.deinit();
    harness.server.config.now_ms = EarlyDataFixture.now_ms;
    harness.server.config.strike_register = &register;

    var reassembly: [16 * 1024]u8 = undefined;
    var resumption: ClientHandshake.Resumption = .{
        .identity = "ticket",
        .obfuscated_age = 250 +% EarlyDataFixture.age_add,
        .psk = undefined,
        .psk_bytes = 32,
        .early_data = .{ .bytes_max = 1024, .suite = .aes_128_gcm_sha256 },
    };
    @memset(&resumption.psk, 0);
    @memcpy(resumption.psk[0..EarlyDataFixture.psk.len], &EarlyDataFixture.psk);
    var client = ClientHandshake.init(&.{
        .client_random = .{0x2c} ** 32,
        .x25519_private = client_x25519_private,
        .session_id = &(.{0x33} ** 32),
        .server_name = "spike.zoxy.test",
        .certificate_policy = .insecure_no_verification,
        .resume_session = resumption,
        .reassembly = &reassembly,
    });
    defer client.deinit();

    const hello = client.start(&client_out);
    // Offered, and keyed: `sendEarlyData` answers bytes rather than null.
    const early = (try client.sendEarlyData("GET /0rtt HTTP/1.1\r\n\r\n", &early_out)).?;

    var hello_storage: [record.wire_record_bytes_max]u8 = undefined;
    @memcpy(hello_storage[0..hello.len], hello);
    const flight = (try harness.server.handleRecord(hello_storage[0..hello.len], &server_out)).?;
    try testing.expectEqual(std.meta.activeTag(flight), .send);
    try testing.expect(harness.server.early_data_accepted);
    // Copied out before anything else touches `server_out`, which the
    // very next `handleRecord` does.
    var flight_storage: [2 * record.wire_record_bytes_max]u8 = undefined;
    @memcpy(flight_storage[0..flight.send.len], flight.send);
    const flight_bytes = flight_storage[0..flight.send.len];

    // The server reads what the client sent, under a secret neither of
    // them exchanged.
    const early_event = (try harness.server.handleRecord(early, &server_out)).?;
    try testing.expectEqualSlices(u8, "GET /0rtt HTTP/1.1\r\n\r\n", early_event.application_data);

    // And the handshake completes, which only works if both ends agree
    // that EndOfEarlyData belongs in the client Finished's transcript
    // (§4.4) and not in the application secrets (§7.1).
    var reply: []const u8 = &.{};
    var index: usize = 0;
    var count: u8 = 0;
    while (index < flight_bytes.len) : (count += 1) {
        try testing.expect(count < 8);
        const length = std.mem.readInt(u16, flight_bytes[index + 3 ..][0..2], .big);
        const one = flight_bytes[index..][0 .. record.header_bytes + length];
        if (try client.handleRecord(one, &client_out)) |event| switch (event) {
            .connected => |bytes| reply = bytes,
            else => return error.TestUnexpectedResult,
        };
        index += one.len;
    }
    try testing.expect(client.early_data_accepted);
    try testing.expect(reply.len >= 1);

    var final: ?ServerHandshake.Event = null;
    index = 0;
    count = 0;
    while (index < reply.len) : (count += 1) {
        try testing.expect(count < 8);
        const length = std.mem.readInt(u16, reply[index + 3 ..][0..2], .big);
        const one = reply[index..][0 .. record.header_bytes + length];
        if (try harness.server.handleRecord(one, &server_out)) |event| final = event;
        index += one.len;
    }
    try testing.expectEqual(std.meta.activeTag(final.?), .connected);
    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);
    try testing.expect(harness.server.resumed);
}

/// A resumed client offering 0-RTT on the terms a test picks. Split out
/// so the suite can vary — which is the whole point of the test below.
fn offeringClient(
    reassembly: []u8,
    psk: []const u8,
    terms: ?ClientHandshake.EarlyData,
) ClientHandshake {
    var resumption: ClientHandshake.Resumption = .{
        .identity = "ticket",
        .obfuscated_age = 250 +% EarlyDataFixture.age_add,
        .psk = undefined,
        .psk_bytes = @intCast(psk.len),
        .early_data = terms,
    };
    @memset(&resumption.psk, 0);
    @memcpy(resumption.psk[0..psk.len], psk);
    return ClientHandshake.init(&.{
        .client_random = .{0x2c} ** 32,
        .x25519_private = client_x25519_private,
        .session_id = &(.{0x33} ** 32),
        .certificate_policy = .insecure_no_verification,
        .resume_session = resumption,
        .reassembly = reassembly,
    });
}

test "§4.2.10: early keys follow the ticket's suite, not the PSK's length" {
    // Two suites share SHA-256, so a 32-byte PSK does not settle which
    // AEAD the early records are sealed under. A binder can afford that
    // ambiguity — it needs only the hash — and early data cannot: the
    // key length differs, the AEAD differs, and a server that derives
    // the other one answers bad_record_mac and kills the connection.
    //
    // This is the test that would have caught it. The two clients differ
    // in exactly one field.
    const psk = [_]u8{0x7e} ** 32;
    var aes_reassembly: [16 * 1024]u8 = undefined;
    var chacha_reassembly: [16 * 1024]u8 = undefined;
    var aes_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var chacha_out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var aes_early: [record.wire_record_bytes_max]u8 = undefined;
    var chacha_early: [record.wire_record_bytes_max]u8 = undefined;

    var aes = offeringClient(&aes_reassembly, &psk, .{
        .bytes_max = 1024,
        .suite = .aes_128_gcm_sha256,
    });
    defer aes.deinit();
    var chacha = offeringClient(&chacha_reassembly, &psk, .{
        .bytes_max = 1024,
        .suite = .chacha20_poly1305_sha256,
    });
    defer chacha.deinit();

    _ = aes.start(&aes_out);
    _ = chacha.start(&chacha_out);
    const under_aes = (try aes.sendEarlyData("same plaintext", &aes_early)).?;
    const under_chacha = (try chacha.sendEarlyData("same plaintext", &chacha_early)).?;

    // Same hello, same PSK, same plaintext — and different ciphertext,
    // because the suite the ticket named reached the key schedule. If it
    // had not, these would be byte-identical.
    try testing.expect(!std.mem.eql(u8, under_aes, under_chacha));
    // AES-128-GCM keys are 16 bytes and ChaCha20's are 32, so the two
    // records are not even the same length of ciphertext for the same
    // input under §5.2's framing... they are, in fact, and that is why
    // the comparison above is on content: the tag and the AEAD differ,
    // the framing does not.
    try testing.expectEqual(under_aes.len, under_chacha.len);
}

test "§4.2.10: what a client will not offer, and will not overspend" {
    const psk = [_]u8{0x7e} ** 32;
    var reassembly: [16 * 1024]u8 = undefined;
    var out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var early_out: [record.wire_record_bytes_max]u8 = undefined;

    // No terms: `sendEarlyData` answers null rather than failing. "This
    // connection is not doing 0-RTT" is an ordinary answer, and the data
    // belongs on the 1-RTT stream instead.
    {
        var client = offeringClient(&reassembly, &psk, null);
        defer client.deinit();
        _ = client.start(&out);
        try testing.expectEqual(
            @as(?[]const u8, null),
            try client.sendEarlyData("nowhere to go", &early_out),
        );
    }

    // A limit of zero is a server that advertised none, so there is
    // nothing to offer against and the extension does not go out.
    {
        var client = offeringClient(&reassembly, &psk, .{
            .bytes_max = 0,
            .suite = .aes_128_gcm_sha256,
        });
        defer client.deinit();
        _ = client.start(&out);
        try testing.expect(!client.early_data_offered);
        try testing.expectEqual(
            @as(?[]const u8, null),
            try client.sendEarlyData("still nowhere", &early_out),
        );
    }

    // And the ticket's limit is a promise the server sized its own
    // ceiling against, so going past it is this client's fault.
    {
        var client = offeringClient(&reassembly, &psk, .{
            .bytes_max = 8,
            .suite = .aes_128_gcm_sha256,
        });
        defer client.deinit();
        _ = client.start(&out);
        try testing.expect(client.early_data_offered);
        _ = (try client.sendEarlyData("12345678", &early_out)).?;
        try testing.expectError(
            error.TooMuchEarlyData,
            client.sendEarlyData("9", &early_out),
        );
    }
}

test "§4.1.2: a HelloRetryRequest withdraws the 0-RTT offer, keys and all" {
    // The second ClientHello does not carry `early_data` — that much was
    // already true, because the retry builds its hello without one. What
    // was not true is that the *state* went with it: the keys were
    // derived over CH1, whose transcript the retry has just replaced, so
    // anything still holding them would seal against a hello the server
    // never saw. A server answering `early_data` after a retry would
    // then have been believed.
    const psk = [_]u8{0x7e} ** 32;
    var reassembly: [16 * 1024]u8 = undefined;
    var out: [2 * record.wire_record_bytes_max]u8 = undefined;
    var early_out: [record.wire_record_bytes_max]u8 = undefined;

    var resumption: ClientHandshake.Resumption = .{
        .identity = "ticket",
        .obfuscated_age = 250 +% EarlyDataFixture.age_add,
        .psk = undefined,
        .psk_bytes = 32,
        .early_data = .{ .bytes_max = 1024, .suite = .aes_128_gcm_sha256 },
    };
    @memset(&resumption.psk, 0);
    @memcpy(resumption.psk[0..psk.len], &psk);
    var client = ClientHandshake.init(&.{
        .client_random = .{0x2c} ** 32,
        .x25519_private = client_x25519_private,
        .session_id = &(.{0x33} ** 32),
        .certificate_policy = .insecure_no_verification,
        .resume_session = resumption,
        .retry_key_share_private = .{0x71} ** 48,
        .reassembly = &reassembly,
    });
    defer client.deinit();

    _ = client.start(&out);
    try testing.expect(client.early_data_offered);
    _ = (try client.sendEarlyData("sent under CH1", &early_out)).?;

    // A retry into a group we advertised.
    var message_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    const retry = server_messages.helloRetryRequest(
        &message_buffer,
        &(.{0x33} ** 32),
        .aes_128_gcm_sha256,
        client_hello.group_secp256r1,
    );
    var retry_record: [record.wire_record_bytes_max]u8 = undefined;
    const framed = frameHandshake(&retry_record, retry);
    const second = (try client.handleRecord(framed, &out)).?;
    try testing.expectEqual(std.meta.activeTag(second), .send);

    // The offer is gone in every sense: not on CH2's wire, not in the
    // state a server's acceptance would be checked against, and not
    // sealable any more.
    try testing.expect(!client.early_data_offered);
    try testing.expectEqual(
        @as(?[]const u8, null),
        try client.sendEarlyData("after the retry", &early_out),
    );
    const hello = client_hello.parse(lastRecordOf(second.send)[record.header_bytes..]) catch
        return error.TestUnexpectedResult;
    try testing.expect(!hello.early_data);
}

/// The last record in a run of them — a client flight may lead with
/// §D.4's compatibility CCS.
fn lastRecordOf(bytes: []const u8) []const u8 {
    var index: usize = 0;
    var last: []const u8 = &.{};
    while (index < bytes.len) {
        const length = std.mem.readInt(u16, bytes[index + 3 ..][0..2], .big);
        last = bytes[index..][0 .. record.header_bytes + length];
        index += last.len;
    }
    return last;
}
