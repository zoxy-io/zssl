//! Resumption (slice 3): the binder chain and PSK-mixed ladder pinned
//! against RFC 8448 §4, and ticket issuance → resumed session end to end,
//! with the client deriving every PSK from its own resumption_master —
//! agreement between the two derivations is the check.

const std = @import("std");
const testing = std.testing;

const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("record.zig");
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
    const backend = @import("crypto/backend_openssl.zig");
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
