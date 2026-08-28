//! A test-only TLS 1.3 client built from zssl's own primitives.
//!
//! Honesty about what this proves: the crypto underneath is shared with
//! the server (RFC 8448 pins that side independently), so what this
//! client exercises is the server's *state machine* — negotiation,
//! ordering, fragmentation, HelloRetryRequest, alerts — plus one genuine
//! second implementation: CertificateVerify is checked through
//! `std.crypto`'s ECDSA, not libcrypto's. Full no-shared-code interop is
//! the slice-5 ladder (BoGo, openssl s_client, `std.crypto.tls.Client`).

const std = @import("std");
const assert = std.debug.assert;

const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const protect = @import("protect.zig");
const record = @import("record.zig");
const record_buffer = @import("record_buffer.zig");
const server_messages = @import("server_messages.zig");
const transcript = @import("transcript.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;

pub const Options = struct {
    session_id: []const u8 = &.{},
    /// Offer an x25519 key share in the first ClientHello. Off forces the
    /// server down the HelloRetryRequest path.
    offer_x25519_share: bool = true,
    /// The group whose share this client offers and completes. The
    /// scalar is stretched from the 32-byte constant every caller passes
    /// — fine in a test client, and exactly the thing the library
    /// refuses to do (DESIGN.md §1: entropy is the embedder's).
    group: backend.Group = .x25519,
    /// A P-256 KeyShareEntry of the right length carrying a point that is
    /// not on the curve — the parser admits it and the key exchange must
    /// be what refuses it.
    offer_bogus_p256_share: bool = false,
    /// Omit psk_key_exchange_modes. Beside a PSK offer that is §4.2.9's
    /// missing_extension; alone it is a hello with nothing for a ticket
    /// to be incompatible with, so a ticket is still permitted — see
    /// `ServerHandshake.ticketPermitted`. Advertising modes that exclude
    /// psk_dhe_ke is the case that forbids one, and `psk_mode_byte`
    /// reaches it.
    omit_psk_modes: bool = false,
    /// Omit the key_share extension outright, rather than sending an
    /// empty one. §9.2 makes that a missing_extension; an empty
    /// `client_shares` is the legal §4.2.8 request for the server's
    /// choice, and the server has to tell them apart.
    omit_key_share: bool = false,
    /// Offer a fake P-256 share beside (or instead of) the x25519 one.
    offer_unsupported_decoy: bool = false,
    /// Cipher suites to offer, wire order; null offers all three.
    suites_wire: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    send_change_cipher_spec: bool = true,
    /// Offer this ticket's PSK for resumption (§4.2.11).
    resume_with: ?*const Ticket = null,
    /// The psk_key_exchange_modes byte sent when resuming; 0x01 is
    /// psk_dhe_ke, anything else makes the server ignore the offer.
    psk_mode_byte: u8 = 0x01,
    /// Flip a binder bit — the offer must then be fatally refused.
    corrupt_binder: bool = false,
};

/// A captured NewSessionTicket plus the PSK the client derived for it
/// from its own resumption_master — independently of the server's copy.
pub const Ticket = struct {
    lifetime_s: u32,
    age_add: u32,
    nonce: [16]u8,
    nonce_bytes: u8,
    ticket: [256]u8,
    ticket_bytes: u16,
    psk: [cipher_suite.hash_bytes_max]u8,
    psk_bytes: u8,
};

pub fn TestClient(comptime suite: CipherSuite) type {
    const Hash = CipherSuite.HashType(suite);
    const Schedule = key_schedule.KeySchedule(suite);
    const Transcript = transcript.Transcript(Hash);
    const hash_bytes = Hash.digest_length;

    return struct {
        options: Options,
        x25519_private: [32]u8,
        scalar_storage: [backend.group_private_bytes_max]u8,
        state: ClientState,
        transcript: Transcript,
        schedule: ?Schedule,
        client_handshake_traffic: [hash_bytes]u8,
        server_handshake_traffic: [hash_bytes]u8,
        finished_hash: [hash_bytes]u8,
        leaf_der: []const u8,
        leaf_storage: [4096]u8,
        transmit_keys: Schedule.TrafficKeys,
        receive_keys: Schedule.TrafficKeys,
        recv: ?protect.Protector,
        send: ?protect.Protector,
        records: record_buffer.RecordBuffer,
        assembler: handshake.Assembler,
        records_storage: [2 * record.wire_record_bytes_max]u8,
        assembler_storage: [16384]u8,
        hello_storage: [1024]u8,
        hello_bytes: usize,
        resumption_master: [hash_bytes]u8,
        tickets: [4]Ticket,
        ticket_count: u8,
        /// Facts the tests assert on afterwards.
        saw_retry: bool,
        certificate_verified: bool,
        alpn_selected: bool,
        psk_accepted: bool,

        const Self = @This();

        const ClientState = enum(u8) { awaiting_server_hello, awaiting_flight, connected, closed };

        pub const Event = union(enum) {
            none,
            /// Bytes for the server, sliced from the caller's out buffer.
            send: []const u8,
            connected: []const u8,
            application_data: []const u8,
            closed,
        };

        pub const Error = protect.Error || backend.Error || handshake.Assembler.Error ||
            record_buffer.RecordBuffer.Error || wire.Error ||
            error{ UnexpectedMessage, BadServerHello, BadSignature, BadFinished, BadCertificate };

        /// The private scalar for the configured group, stretched from
        /// the 32-byte constant callers pass. A test client may do that;
        /// the library may not.
        fn scalar(self: *const Self) []const u8 {
            const wanted = self.options.group.privateBytes();
            assert(wanted <= self.scalar_storage.len);
            return self.scalar_storage[0..wanted];
        }

        pub fn init(x25519_private: *const [32]u8, options: *const Options) Self {
            assert(options.session_id.len <= 32);
            assert(!std.mem.allEqual(u8, x25519_private, 0));
            var client: Self = .{
                .options = options.*,
                .x25519_private = x25519_private.*,
                .scalar_storage = x25519_private.* ++ x25519_private[0..16].*,
                .state = .awaiting_server_hello,
                .transcript = .empty,
                .schedule = null,
                .client_handshake_traffic = undefined,
                .server_handshake_traffic = undefined,
                .finished_hash = undefined,
                .leaf_der = &.{},
                .leaf_storage = undefined,
                .transmit_keys = undefined,
                .receive_keys = undefined,
                .recv = null,
                .send = null,
                .records = undefined,
                .assembler = undefined,
                .records_storage = undefined,
                .assembler_storage = undefined,
                .hello_storage = undefined,
                .hello_bytes = 0,
                .resumption_master = undefined,
                .tickets = undefined,
                .ticket_count = 0,
                .saw_retry = false,
                .certificate_verified = false,
                .alpn_selected = false,
                .psk_accepted = false,
            };
            client.records = record_buffer.RecordBuffer.init(&client.records_storage);
            client.assembler = handshake.Assembler.init(&client.assembler_storage);
            return client;
        }

        pub fn deinit(self: *Self) void {
            assert(self.state != .awaiting_server_hello or self.schedule == null);
            if (self.recv) |*protector| protector.deinit();
            if (self.send) |*protector| protector.deinit();
            if (self.schedule) |*schedule| schedule.wipe();
            self.* = undefined;
        }

        /// The opening flight: one plaintext handshake record with the
        /// ClientHello. The message is kept for HRR transcript surgery.
        pub fn helloRecord(self: *Self, out: []u8) []const u8 {
            assert(self.state == .awaiting_server_hello);
            assert(out.len >= record.header_bytes + self.hello_storage.len);
            const message = self.buildHello(self.options.offer_x25519_share, self.options.offer_unsupported_decoy);
            self.transcript.update(message);
            var builder = wire.Builder.init(out);
            appendPlaintextRecord(&builder, .handshake, message);
            return builder.written();
        }

        fn buildHello(self: *Self, with_x25519: bool, with_decoy: bool) []const u8 {
            var builder = wire.Builder.init(&self.hello_storage);
            const message = handshake.beginMessage(&builder, .client_hello);
            builder.putU16(0x0303);
            var random: [32]u8 = undefined;
            for (&random, 0..) |*byte, index| byte.* = @truncate(index * 7 + 3);
            builder.putSlice(&random);
            builder.putByte(@intCast(self.options.session_id.len));
            builder.putSlice(self.options.session_id);
            if (self.options.suites_wire) |suites| {
                assert(suites.len % 2 == 0);
                builder.putU16(@intCast(suites.len));
                builder.putSlice(suites);
            } else {
                builder.putU16(6);
                builder.putU16(@intFromEnum(suite));
                inline for (.{ CipherSuite.aes_128_gcm_sha256, CipherSuite.chacha20_poly1305_sha256 }) |filler| {
                    if (filler != suite) builder.putU16(@intFromEnum(filler));
                }
                if (suite != .aes_256_gcm_sha384) builder.putU16(@intFromEnum(CipherSuite.aes_256_gcm_sha384));
            }
            builder.putByte(1);
            builder.putByte(0);
            const extensions = builder.markU16();
            self.buildHelloExtensions(&builder, with_x25519, with_decoy);
            builder.patchU16(extensions);
            handshake.endMessage(&builder, message);
            self.hello_bytes = builder.written().len;
            if (self.options.resume_with != null) self.patchBinder();
            return builder.written();
        }

        /// §4.2.11.2: the binder MACs the hash of the ClientHello minus
        /// its own binders section, so it can only be computed — and
        /// patched in — after the rest of the message is final.
        fn patchBinder(self: *Self) void {
            const ticket = self.options.resume_with.?;
            assert(ticket.psk_bytes == hash_bytes);
            const message = self.hello_storage[0..self.hello_bytes];
            const binders_section_bytes = 2 + 1 + hash_bytes;
            assert(message.len > binders_section_bytes);
            const truncated = message[0 .. message.len - binders_section_bytes];
            var truncated_hash: [hash_bytes]u8 = undefined;
            Hash.hash(truncated, &truncated_hash, .{});
            var schedule = Schedule.initEarly(ticket.psk[0..hash_bytes]);
            var binder = schedule.resumptionBinder(&truncated_hash);
            schedule.wipe();
            if (self.options.corrupt_binder) binder[0] ^= 0x01;
            @memcpy(message[message.len - hash_bytes ..], &binder);
        }

        fn buildHelloExtensions(self: *Self, builder: *wire.Builder, with_x25519: bool, with_decoy: bool) void {
            assert(builder.index >= 40);
            if (self.options.server_name) |name| {
                builder.putU16(0); // server_name
                const body = builder.markU16();
                const list = builder.markU16();
                builder.putByte(0);
                const name_mark = builder.markU16();
                builder.putSlice(name);
                builder.patchU16(name_mark);
                builder.patchU16(list);
                builder.patchU16(body);
            }
            builder.putU16(10); // supported_groups: x25519 and P-256.
            const groups = builder.markU16();
            const group_list = builder.markU16();
            builder.putU16(client_hello.group_x25519);
            builder.putU16(0x0017);
            builder.patchU16(group_list);
            builder.patchU16(groups);
            builder.putU16(13); // signature_algorithms: both ECDSA schemes.
            const schemes = builder.markU16();
            const scheme_list = builder.markU16();
            builder.putU16(0x0403);
            builder.putU16(0x0503);
            builder.patchU16(scheme_list);
            builder.patchU16(schemes);
            if (self.options.alpn) |protocol| {
                builder.putU16(16);
                const body = builder.markU16();
                const list = builder.markU16();
                builder.putByte(@intCast(protocol.len));
                builder.putSlice(protocol);
                builder.patchU16(list);
                builder.patchU16(body);
            }
            builder.putU16(43); // supported_versions
            const versions = builder.markU16();
            builder.putByte(2);
            builder.putU16(0x0304);
            builder.patchU16(versions);
            // Stop here: supported_groups is written, key_share is not,
            // which is the §9.2 shape. The caller closes the extension
            // block.
            //
            // Returning early also skips `buildPskExtensions`, while
            // `buildHello` still patches a binder whenever `resume_with`
            // is set — which would write binder bytes over the tail of
            // whatever extension came last. The two options are
            // incompatible, so say so here rather than let a future
            // caller debug a silently corrupted hello.
            if (self.options.omit_key_share) {
                assert(self.options.resume_with == null);
                return;
            }
            builder.putU16(51); // key_share
            const shares = builder.markU16();
            const share_list = builder.markU16();
            if (self.options.offer_bogus_p256_share) {
                builder.putU16(@intFromEnum(backend.Group.secp256r1));
                builder.putU16(65);
                builder.putByte(0x04);
                builder.putSlice(&(.{0x5a} ** 64));
            }
            if (with_decoy) {
                // secp521r1: a group zssl does not hold, so the share is
                // unusable and the server must retry. It used to be
                // P-256, which zssl now *does* hold — a decoy has to be
                // a group we genuinely cannot complete or it stops
                // testing HelloRetryRequest at all.
                builder.putU16(0x0019);
                builder.putU16(133);
                builder.putByte(0x04);
                builder.putSlice(&(.{0x5a} ** 132));
            }
            if (with_x25519) {
                // Unreachable rather than propagated: the scalar is a
                // fixed nonzero test constant (asserted at init), so the
                // only failure left is a libcrypto fault, which a test run
                // should crash on rather than dress up as a peer error.
                var public_buffer: [backend.group_public_bytes_max]u8 = undefined;
                const group = self.options.group;
                const public = backend.keySharePublic(
                    group,
                    self.scalar(),
                    &public_buffer,
                ) catch unreachable;
                builder.putU16(@intFromEnum(group));
                builder.putU16(@intCast(public.len));
                builder.putSlice(public);
            }
            builder.patchU16(share_list);
            builder.patchU16(shares);
            if (!self.options.omit_psk_modes) self.buildPskModes(builder);
            // §4.2: pre_shared_key is last, so it stays after the modes.
            if (self.options.resume_with != null) self.buildPskExtensions(builder);
        }

        /// psk_key_exchange_modes plus the pre_shared_key offer, which
        /// §4.2 requires to be the last extension. The binder is written
        /// as zeros here and patched by `buildHello` once the message is
        /// complete — §4.2.11.2's truncated-transcript dance.
        /// §4.2.9, on every hello rather than only when resuming, because
        /// the extension governs the tickets a server may *send* as well
        /// as the PSKs a client may offer — a test client that only ever
        /// sent it while resuming could not exercise the outbound half of
        /// that rule at all. `client_messages.zig` sends it
        /// unconditionally for the same reason.
        fn buildPskModes(self: *Self, builder: *wire.Builder) void {
            builder.putU16(45); // psk_key_exchange_modes
            const modes = builder.markU16();
            builder.putByte(1);
            builder.putByte(self.options.psk_mode_byte);
            builder.patchU16(modes);
        }

        fn buildPskExtensions(self: *Self, builder: *wire.Builder) void {
            const ticket = self.options.resume_with.?;
            assert(ticket.psk_bytes == hash_bytes);
            assert(ticket.ticket_bytes >= 1);
            builder.putU16(41); // pre_shared_key
            const extension = builder.markU16();
            const identities = builder.markU16();
            builder.putU16(ticket.ticket_bytes);
            builder.putSlice(ticket.ticket[0..ticket.ticket_bytes]);
            builder.putU32(ticket.age_add); // Obfuscated age; policy is the server's.
            builder.patchU16(identities);
            const binders = builder.markU16();
            builder.putByte(hash_bytes);
            builder.putSlice(&(.{0} ** hash_bytes));
            builder.patchU16(binders);
            builder.patchU16(extension);
        }

        /// Feed server bytes (any chunking); act on what comes back.
        pub fn absorb(self: *Self, bytes: []const u8, out: []u8) Error!Event {
            assert(bytes.len >= 1);
            assert(out.len >= record.wire_record_bytes_max);
            try self.records.push(bytes);
            var result: Event = .none;
            var records_seen: u8 = 0;
            while (try self.records.next()) |one| : (records_seen += 1) {
                assert(records_seen < 16); // A test exchange is a handful of records.
                const event = try self.handleRecord(one, out);
                if (event != .none) {
                    // One actionable event per absorb keeps tests explicit.
                    assert(result == .none);
                    result = event;
                }
            }
            return result;
        }

        fn handleRecord(self: *Self, one: []const u8, out: []u8) Error!Event {
            const header = record.parseHeader(one[0..record.header_bytes]) catch
                return error.UnexpectedMessage;
            switch (header.content_type) {
                .change_cipher_spec => return .none,
                .alert => return error.UnexpectedMessage,
                .handshake => {
                    if (self.state != .awaiting_server_hello) return error.UnexpectedMessage;
                    try self.assembler.push(one[record.header_bytes..]);
                    const message = (try self.assembler.next()) orelse return .none;
                    if (message.messageType() != .server_hello) return error.BadServerHello;
                    return self.handleServerHello(message.bytes, out);
                },
                .application_data => return self.handleProtected(one, out),
            }
        }

        fn handleServerHello(self: *Self, message: []const u8, out: []u8) Error!Event {
            var body = wire.Cursor.init(message[handshake.header_bytes..]);
            if (try body.takeU16() != 0x0303) return error.BadServerHello;
            const random = try body.takeSlice(32);
            const echo_bytes = try body.takeByte();
            _ = try body.takeSlice(echo_bytes);
            const suite_wire = try body.takeU16();
            if (CipherSuite.fromWire(suite_wire) != suite) return error.BadServerHello;
            if (try body.takeByte() != 0) return error.BadServerHello;
            const is_retry = std.mem.eql(u8, random, &server_messages.hello_retry_magic);
            var server_share_buffer: [backend.group_public_bytes_max]u8 = undefined;
            var server_share_bytes: ?u8 = null;
            const extensions_bytes = try body.takeU16();
            if (extensions_bytes != body.remaining()) return error.BadServerHello;
            var extensions_seen: u8 = 0;
            while (body.remaining() > 0) : (extensions_seen += 1) {
                if (extensions_seen == 8) return error.BadServerHello;
                const extension_type = try body.takeU16();
                const data = try body.takeSlice(try body.takeU16());
                if (extension_type == 51 and !is_retry) {
                    var share = wire.Cursor.init(data);
                    const group = self.options.group;
                    if (try share.takeU16() != @intFromEnum(group)) return error.BadServerHello;
                    const expected = group.publicBytes();
                    if (try share.takeU16() != expected) return error.BadServerHello;
                    const bytes = try share.takeSlice(expected);
                    @memcpy(server_share_buffer[0..expected], bytes);
                    server_share_bytes = expected;
                }
                if (extension_type == 41) {
                    // The server accepted our PSK; we only ever offer one.
                    if (self.options.resume_with == null) return error.BadServerHello;
                    var selected = wire.Cursor.init(data);
                    if (try selected.takeU16() != 0) return error.BadServerHello;
                    self.psk_accepted = true;
                }
            }
            if (is_retry) return self.handleRetry(message, out);
            self.transcript.update(message);
            const share_bytes = server_share_bytes orelse return error.BadServerHello;
            try self.startHandshakeKeys(server_share_buffer[0..share_bytes]);
            self.state = .awaiting_flight;
            return .none;
        }

        /// §4.1.4 client side: replace CH1 with its hash, absorb the HRR,
        /// and answer with a ClientHello that carries the demanded share.
        fn handleRetry(self: *Self, hrr: []const u8, out: []u8) Error!Event {
            if (self.saw_retry) return error.BadServerHello;
            // Retry-with-PSK would need the binder recomputed over the
            // §4.4.1 surgery transcript; the server ignores that combo
            // and this client never exercises it.
            assert(self.options.resume_with == null);
            self.saw_retry = true;
            assert(self.transcript.messages_seen == 1);
            var ch1_hash: [hash_bytes]u8 = undefined;
            Hash.hash(self.hello_storage[0..self.hello_bytes], &ch1_hash, .{});
            self.transcript = .empty;
            const synthetic = [handshake.header_bytes]u8{ 254, 0, 0, hash_bytes };
            self.transcript.state.update(&synthetic);
            self.transcript.state.update(&ch1_hash);
            self.transcript.messages_seen = 1;
            self.transcript.update(hrr);
            const retry_hello = self.buildHello(true, false);
            self.transcript.update(retry_hello);
            var builder = wire.Builder.init(out);
            appendPlaintextRecord(&builder, .handshake, retry_hello);
            return .{ .send = builder.written() };
        }

        fn startHandshakeKeys(self: *Self, server_share: []const u8) Error!void {
            assert(self.schedule == null);
            var shared_buffer: [backend.group_shared_bytes_max]u8 = undefined;
            defer std.crypto.secureZero(u8, &shared_buffer);
            const shared = try backend.keyShareShared(
                self.options.group,
                self.scalar(),
                server_share,
                &shared_buffer,
            );
            const psk: ?[]const u8 = if (self.psk_accepted)
                self.options.resume_with.?.psk[0..hash_bytes]
            else
                null;
            var schedule = Schedule.initEarly(psk);
            schedule.advanceToHandshake(shared);
            const hello_hash = self.transcript.currentHash();
            self.client_handshake_traffic = schedule.deriveAt(.handshake, "c hs traffic", &hello_hash);
            self.server_handshake_traffic = schedule.deriveAt(.handshake, "s hs traffic", &hello_hash);
            const receive_keys = Schedule.trafficKeys(&self.server_handshake_traffic);
            const transmit_keys = Schedule.trafficKeys(&self.client_handshake_traffic);
            self.recv = try protect.Protector.init(suite, &receive_keys.key, &receive_keys.iv);
            errdefer {
                self.recv.?.deinit();
                self.recv = null;
            }
            self.send = try protect.Protector.init(suite, &transmit_keys.key, &transmit_keys.iv);
            self.schedule = schedule;
        }

        fn handleProtected(self: *Self, one: []const u8, out: []u8) Error!Event {
            if (self.state == .awaiting_server_hello) return error.UnexpectedMessage;
            var plaintext_buffer: [record.wire_record_bytes_max]u8 = undefined;
            const opened = try self.recv.?.open(one, &plaintext_buffer);
            const plaintext = plaintext_buffer[0..opened.plaintext_bytes];
            switch (opened.content_type) {
                .alert => {
                    self.state = .closed;
                    return .closed;
                },
                .handshake => {
                    try self.assembler.push(plaintext);
                    if (self.state == .connected) return self.drainTickets();
                    if (self.state != .awaiting_flight) return error.UnexpectedMessage;
                    return self.drainFlight(out);
                },
                .application_data => {
                    if (self.state != .connected) return error.UnexpectedMessage;
                    assert(plaintext.len <= out.len);
                    @memcpy(out[0..plaintext.len], plaintext);
                    return .{ .application_data = out[0..plaintext.len] };
                },
                .change_cipher_spec => return error.UnexpectedMessage,
            }
        }

        fn drainFlight(self: *Self, out: []u8) Error!Event {
            var messages_seen: u8 = 0;
            while (try self.assembler.next()) |message| : (messages_seen += 1) {
                assert(messages_seen < 8); // EE, Certificate, CV, Finished.
                switch (message.messageType() orelse return error.UnexpectedMessage) {
                    .encrypted_extensions => {
                        self.alpn_selected = std.mem.indexOf(u8, message.body(), "http/1.1") != null;
                        self.transcript.update(message.bytes);
                    },
                    .certificate => {
                        try self.leafFromCertificate(message.body());
                        self.transcript.update(message.bytes);
                    },
                    .certificate_verify => try self.verifyServerSignature(message),
                    .finished => return self.finishHandshake(message, out),
                    else => return error.UnexpectedMessage,
                }
            }
            return .none;
        }

        fn leafFromCertificate(self: *Self, body: []const u8) Error!void {
            // context length (0), u24 list, u24 leaf length, leaf DER.
            var cursor = wire.Cursor.init(body);
            const context_bytes = try cursor.takeByte();
            if (context_bytes != 0) return error.BadCertificate;
            _ = try cursor.takeU24();
            const leaf_bytes = try cursor.takeU24();
            if (leaf_bytes == 0) return error.BadCertificate;
            const der = try cursor.takeSlice(leaf_bytes);
            assert(der.len >= 1);
            assert(der.len <= self.leaf_storage.len);
            @memcpy(self.leaf_storage[0..der.len], der);
            self.leaf_der = self.leaf_storage[0..der.len];
        }

        /// The independent leg: verify CertificateVerify with std.crypto's
        /// ECDSA over the certificate's own public key — no libcrypto.
        fn verifyServerSignature(self: *Self, message: handshake.Message) Error!void {
            assert(self.leaf_der.len >= 1);
            var body = wire.Cursor.init(message.body());
            const scheme = try body.takeU16();
            if (scheme != 0x0403) return error.BadSignature; // Fixture is P-256.
            const signature_der = try body.takeSlice(try body.takeU16());
            var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
            const content = server_messages.certificateVerifyContent(
                .server,
                &self.transcript.currentHash(),
                &content_buffer,
            );
            const certificate: std.crypto.Certificate = .{ .buffer = self.leaf_der, .index = 0 };
            const parsed = certificate.parse() catch return error.BadCertificate;
            const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            const public_key = Ecdsa.PublicKey.fromSec1(parsed.pubKey()) catch return error.BadCertificate;
            const signature = Ecdsa.Signature.fromDer(signature_der) catch return error.BadSignature;
            signature.verify(content, public_key) catch return error.BadSignature;
            self.certificate_verified = true;
            self.transcript.update(message.bytes);
        }

        /// §4.6.1 client side: capture tickets and derive each one's PSK
        /// from our own resumption_master — independently of the server's
        /// copy, which is what makes the next session's success a check.
        fn drainTickets(self: *Self) Error!Event {
            assert(self.state == .connected);
            var messages_seen: u8 = 0;
            while (try self.assembler.next()) |message| : (messages_seen += 1) {
                // Slack over tickets.len is deliberate: storeTicket errors
                // on capacity before this bound can fire.
                assert(messages_seen < 2 * self.tickets.len);
                if (message.messageType() != .new_session_ticket) return error.UnexpectedMessage;
                try self.storeTicket(message.body());
            }
            return .none;
        }

        fn storeTicket(self: *Self, body: []const u8) Error!void {
            assert(self.state == .connected);
            if (self.ticket_count == self.tickets.len) return error.UnexpectedMessage;
            var cursor = wire.Cursor.init(body);
            var entry: Ticket = undefined;
            entry.lifetime_s = try cursor.takeU32();
            entry.age_add = try cursor.takeU32();
            const nonce_bytes = try cursor.takeByte();
            if (nonce_bytes == 0 or nonce_bytes > entry.nonce.len) return error.UnexpectedMessage;
            const nonce = try cursor.takeSlice(nonce_bytes);
            @memcpy(entry.nonce[0..nonce_bytes], nonce);
            entry.nonce_bytes = @intCast(nonce_bytes);
            const ticket_bytes = try cursor.takeU16();
            if (ticket_bytes == 0 or ticket_bytes > entry.ticket.len) return error.UnexpectedMessage;
            const ticket = try cursor.takeSlice(ticket_bytes);
            @memcpy(entry.ticket[0..ticket_bytes], ticket);
            entry.ticket_bytes = ticket_bytes;
            const extensions_bytes = try cursor.takeU16();
            _ = try cursor.takeSlice(extensions_bytes);
            if (cursor.remaining() != 0) return error.UnexpectedMessage;
            const psk = Schedule.resumptionPsk(&self.resumption_master, nonce);
            @memset(&entry.psk, 0);
            @memcpy(entry.psk[0..hash_bytes], &psk);
            entry.psk_bytes = hash_bytes;
            self.tickets[self.ticket_count] = entry;
            self.ticket_count += 1;
            assert(self.ticket_count <= self.tickets.len);
        }

        fn finishHandshake(self: *Self, message: handshake.Message, out: []u8) Error!Event {
            assert(self.certificate_verified or self.psk_accepted);
            assert(self.schedule.?.stage == .handshake);
            if (message.body().len != hash_bytes) return error.BadFinished;
            const server_key = Schedule.finishedKey(&self.server_handshake_traffic);
            const expected = Schedule.verifyData(&server_key, &self.transcript.currentHash());
            if (!std.crypto.timing_safe.eql([hash_bytes]u8, message.body()[0..hash_bytes].*, expected)) {
                return error.BadFinished;
            }
            self.transcript.update(message.bytes);
            self.finished_hash = self.transcript.currentHash();
            self.schedule.?.advanceToMaster();
            const client_ap = self.schedule.?.deriveAt(.master, "c ap traffic", &self.finished_hash);
            const server_ap = self.schedule.?.deriveAt(.master, "s ap traffic", &self.finished_hash);
            self.transmit_keys = Schedule.trafficKeys(&client_ap);
            self.receive_keys = Schedule.trafficKeys(&server_ap);

            const client_key = Schedule.finishedKey(&self.client_handshake_traffic);
            const verify_data = Schedule.verifyData(&client_key, &self.finished_hash);
            var message_buffer: [handshake.header_bytes + hash_bytes]u8 = undefined;
            const finished_message = server_messages.finished(&message_buffer, &verify_data);
            self.transcript.update(finished_message);
            self.resumption_master = self.schedule.?.deriveAt(.master, "res master", &self.transcript.currentHash());
            var builder = wire.Builder.init(out);
            if (self.options.send_change_cipher_spec) {
                builder.putSlice(&server_messages.change_cipher_spec_record);
            }
            const sealed = try self.send.?.seal(.handshake, finished_message, builder.bytes[builder.index..]);
            builder.index += sealed.len;

            self.recv.?.deinit();
            self.send.?.deinit();
            self.recv = null;
            self.send = null;
            self.recv = try protect.Protector.init(suite, &self.receive_keys.key, &self.receive_keys.iv);
            errdefer {
                self.recv.?.deinit();
                self.recv = null;
            }
            self.send = try protect.Protector.init(suite, &self.transmit_keys.key, &self.transmit_keys.iv);
            self.state = .connected;
            return .{ .connected = builder.written() };
        }

        /// Application bytes for the server, once connected.
        pub fn sendApplicationData(self: *Self, bytes: []const u8, out: []u8) Error![]const u8 {
            assert(self.state == .connected);
            assert(bytes.len <= record.plaintext_bytes_max);
            return self.send.?.seal(.application_data, bytes, out);
        }

        pub fn sendClose(self: *Self, out: []u8) Error![]const u8 {
            assert(self.state == .connected);
            const bytes = [2]u8{ 1, 0 }; // warning, close_notify.
            const sealed = try self.send.?.seal(.alert, &bytes, out);
            self.state = .closed;
            return sealed;
        }

        fn appendPlaintextRecord(builder: *wire.Builder, content_type: record.ContentType, payload: []const u8) void {
            assert(payload.len >= 1);
            assert(payload.len <= record.plaintext_bytes_max);
            record.writeHeader(
                .{ .content_type = content_type, .length = @intCast(payload.len) },
                builder.bytes[builder.index..][0..record.header_bytes],
            );
            builder.index += record.header_bytes;
            builder.putSlice(payload);
        }
    };
}
