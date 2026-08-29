//! The server under test for tlsfuzzer (docs/TLSFUZZER.md).
//!
//! tlsfuzzer is a TLS client written in Python over tlslite-ng — a third
//! implementation, by different people, from the one BoGo brings. Where
//! BoGo spawns a shim per case, tlsfuzzer expects a *server it can
//! connect to repeatedly*: one script drives hundreds of conversations,
//! each its own TCP connection, and scores them itself.
//!
//! So this is a long-lived listener rather than a per-case binary. Its
//! whole contract is:
//!
//!   - accept, handshake, and never die on a connection that fails —
//!     most of tlsfuzzer's conversations are *meant* to fail, and a
//!     harness that exits on the first refusal scores one case and then
//!     hangs the rest;
//!   - echo application data back byte for byte, which is the mode
//!     tlsfuzzer's scripts are written against — `test-tls13-lengths`
//!     calls it "echo mode" in its own help text and sends every length
//!     from 1 to 2^14 expecting exactly that many bytes in reply;
//!   - answer a close_notify with a close_notify, which `ExpectAlert`
//!     requires and which `sendAlert` made expressible.
//!
//! It draws its own entropy per connection through `std.Io`, which is
//! the embedder's job and not the library's (DESIGN.md §1).

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const zssl = @import("zssl");
const Credentials = zssl.Credentials;
const ServerHandshake = zssl.ServerHandshake;
const cipher_suite = zssl.cipher_suite;
const record = zssl.record;

/// A conversation that needs more records than this is not a test case,
/// it is a peer that has stopped making progress.
const records_per_phase_max: u32 = 4096;

/// How long one conversation may take. Generous for a loopback
/// exchange, short enough that a deliberately abandoned one does not
/// hold the listener.
const connection_budget_default_s: u64 = 5;

/// Bound a connection by shutting its socket down from a concurrent
/// task, not with `SO_RCVTIMEO`.
///
/// The socket option is the obvious answer and it is wrong here: it
/// makes `read` return EAGAIN, and `std.Io.Threaded` treats EAGAIN on a
/// socket it believes is blocking as a programmer bug and panics. This
/// harness did exactly that, and took the listener down mid-sweep.
///
/// Shutting the socket down instead makes the blocked read return
/// end-of-stream, which is a case every path here already handles — a
/// peer that stopped talking and a peer that hung up look the same, and
/// for a test harness they should.
fn connectionWatchdog(io: Io, stream: Io.net.Stream, budget_ns: u64) void {
    assert(budget_ns >= std.time.ns_per_s);
    io.sleep(Io.Duration.fromNanoseconds(budget_ns), .awake) catch return;
    stream.shutdown(io, .both) catch {};
}

/// The identity we issue tickets under. Opaque to the protocol; sealing
/// is the embedder's job and a harness needs no seal.
const ticket_identity = "zssl-tlsfuzzer-ticket";
const ticket_nonce = [_]u8{0x01};

var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
var reassembly: [64 * 1024]u8 = undefined;
var flight_storage: [Credentials.chain_bytes_max + 1024]u8 = undefined;
var pump_storage: Pump = undefined;

const Options = struct {
    port: u16 = 4433,
    cert_path: []const u8 = "src/testdata/cert.pem",
    key_path: []const u8 = "src/testdata/key.pem",
    alpn: ?[]const u8 = null,
    /// NewSessionTickets to issue per connection. Zero is a legitimate
    /// configuration and some scripts ask for exactly that.
    tickets: u8 = 1,
    /// Seconds one conversation may take. Five is right for tlsfuzzer,
    /// whose scripts are fast and whose abort cases *need* a short
    /// deadline to keep a sequential listener from starving. TLS-Anvil
    /// needs longer: it is a JVM driving combinatorial cases, and under
    /// amd64 emulation a single KeyUpdate conversation can outlast five
    /// seconds — which arrives as "Socket was closed" and reads exactly
    /// like a protocol failure.
    connection_budget_s: u64 = connection_budget_default_s,
};

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const options = try parseArguments(init, arena);

    const cert_pem = try readFile(io, arena, options.cert_path);
    const key_pem = try readFile(io, arena, options.key_path);
    var credentials = try Credentials.load(cert_pem, key_pem, &chain_storage, false);
    defer credentials.deinit();

    // Computed once and handed to each watchdog, rather than parked in
    // a global: the task already takes arguments, so it does not need
    // one.
    const budget_ns = options.connection_budget_s * std.time.ns_per_s;
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(options.port) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    // tlsfuzzer waits for this line before it starts connecting, so it is
    // part of the interface rather than decoration.
    std.debug.print("zssl-tlsfuzzer-server: listening on 127.0.0.1:{d}\n", .{options.port});

    var store: TicketStore = .{};
    var served: u64 = 0;
    while (true) : (served += 1) {
        const stream = listener.accept(io) catch continue;
        // A deadline, because this listener is sequential and a client
        // that stops talking without closing would otherwise hold the
        // accept loop forever — starving every later script rather than
        // failing one conversation. tlsfuzzer's abort cases do that on
        // purpose, so this is a requirement and not a precaution.
        var guard: Io.Group = .init;
        guard.concurrent(io, connectionWatchdog, .{ io, stream, budget_ns }) catch {};
        // Every outcome is per-connection. A conversation the peer meant
        // to fail is the common case here, not the exception.
        serve(io, stream, &credentials, &options, &store) catch {};
        // Cancel before closing: the watchdog holds the same socket, and
        // a shutdown racing a close is a use-after-close.
        guard.cancel(io);
        stream.close(io);
    }
}

fn parseArguments(init: std.process.Init, arena: std.mem.Allocator) !Options {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer iterator.deinit();
    _ = iterator.skip();
    var options: Options = .{};
    while (iterator.next()) |argument| {
        const value = iterator.next() orelse return error.MissingFlagValue;
        if (std.mem.eql(u8, argument, "--port")) {
            options.port = std.fmt.parseInt(u16, value, 10) catch return error.BadFlagValue;
        } else if (std.mem.eql(u8, argument, "--cert")) {
            options.cert_path = value;
        } else if (std.mem.eql(u8, argument, "--key")) {
            options.key_path = value;
        } else if (std.mem.eql(u8, argument, "--alpn")) {
            options.alpn = value;
        } else if (std.mem.eql(u8, argument, "--connection-budget-s")) {
            options.connection_budget_s = std.fmt.parseInt(u64, value, 10) catch return error.BadFlagValue;
            if (options.connection_budget_s == 0) return error.BadFlagValue;
        } else if (std.mem.eql(u8, argument, "--tickets")) {
            options.tickets = std.fmt.parseInt(u8, value, 10) catch return error.BadFlagValue;
        } else {
            return error.UnknownFlag;
        }
    }
    assert(options.port >= 1);
    return options;
}

/// The embedder's ticket state, kept across connections so the
/// resumption scripts have something to come back with. One slot: the
/// scripts offer the ticket they were most recently given.
const TicketStore = struct {
    psk: [cipher_suite.hash_bytes_max]u8 = undefined,
    psk_bytes: u8 = 0,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?u8 {
        _ = obfuscated_age; // Age policy is the embedder's; this one has none.
        const self: *TicketStore = @ptrCast(@alignCast(context));
        if (self.psk_bytes == 0) return null;
        if (!std.mem.eql(u8, identity, ticket_identity)) return null;
        psk_out.* = self.psk;
        return self.psk_bytes;
    }
};

fn serve(
    io: Io,
    stream: Io.net.Stream,
    credentials: *const Credentials,
    options: *const Options,
    store: *TicketStore,
) !void {
    const pump = &pump_storage;
    pump.init(io, stream);

    var entropy: [80]u8 = undefined;
    io.random(&entropy);
    var server = ServerHandshake.init(&.{
        .credentials = credentials,
        .server_random = entropy[0..32].*,
        .key_share_private = entropy[32..80].*,
        .alpn = options.alpn,
        .reassembly = &reassembly,
        .flight = &flight_storage,
        .psk_lookup = .{ .context = store, .lookup = TicketStore.lookup },
    });
    defer server.deinit();

    pump.handshake(&server) catch |err| return pump.abort(&server, err);

    // §4.6.1's ordering: derive the PSK, then seal the ticket that stands
    // for it, and only after `connected`.
    var issued: u8 = 0;
    // §4.6.1 is the library's to enforce: a client that never advertised
    // psk_dhe_ke cannot use a ticket and `sendNewSessionTicket` refuses
    // to mint one. Most tlsfuzzer scripts do not offer the extension, so
    // asking first is what keeps that refusal from failing conversations
    // that are otherwise correct.
    const ticket_count: u8 = if (server.ticketPermitted()) options.tickets else 0;
    while (issued < ticket_count) : (issued += 1) {
        const psk = server.resumptionPsk(&ticket_nonce, &store.psk);
        store.psk_bytes = @intCast(psk.len);
        const sealed = server.sendNewSessionTicket(&.{
            .lifetime_s = 3600,
            .age_add = 0,
            .ticket_nonce = &ticket_nonce,
            .ticket = ticket_identity,
        }, &pump.out) catch |err| return pump.abort(&server, err);
        try pump.write(sealed);
    }

    try pump.converse(&server);
}

const Pump = struct {
    io: Io,
    records: zssl.record_buffer.RecordBuffer,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    read_buffer: [4 * record.wire_record_bytes_max]u8,
    write_buffer: [4 * record.wire_record_bytes_max]u8,
    storage: [4 * record.wire_record_bytes_max]u8,
    out: [4 * record.wire_record_bytes_max]u8,
    /// Where a record's plaintext is held while its echo is sealed back
    /// into `out`. §5.1's cap, because that is the most
    /// `sendApplicationData` accepts in one record.
    echo: [record.plaintext_bytes_max]u8,

    fn init(pump: *Pump, io: Io, stream: Io.net.Stream) void {
        pump.io = io;
        pump.records = zssl.record_buffer.RecordBuffer.init(&pump.storage);
        pump.reader = stream.reader(io, &pump.read_buffer);
        pump.writer = stream.writer(io, &pump.write_buffer);
    }

    fn write(pump: *Pump, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        try pump.writer.interface.writeAll(bytes);
        try pump.writer.interface.flush();
    }

    fn nextRecord(pump: *Pump) ![]const u8 {
        var refills: u32 = 0;
        // How many reads a record takes is the peer's choice, so the
        // bound is an error rather than an assertion.
        while (refills < records_per_phase_max) : (refills += 1) {
            if (try pump.records.next()) |one| return one;
            pump.reader.interface.fill(1) catch return error.PeerClosed;
            const available = pump.reader.interface.buffered();
            assert(available.len >= 1);
            try pump.records.push(available);
            pump.reader.interface.toss(available.len);
        }
        return error.TooManyRecords;
    }

    fn handshake(pump: *Pump, server: *ServerHandshake) !void {
        var records_seen: u32 = 0;
        while (server.state != .connected) : (records_seen += 1) {
            if (records_seen == records_per_phase_max) return error.TooManyRecords;
            const one = try pump.nextRecord();
            switch (try server.handleRecord(one, &pump.out)) {
                .send => |bytes| try pump.write(bytes),
                .none, .connected => {},
                .closed => return error.PeerClosedDuringHandshake,
                .application_data => return error.UnexpectedEvent,
            }
        }
    }

    /// Post-handshake: answer application data, and answer a close_notify
    /// with our own — `ExpectAlert` in the scripts is waiting for it.
    fn converse(pump: *Pump, server: *ServerHandshake) !void {
        var records_seen: u32 = 0;
        while (records_seen < records_per_phase_max) : (records_seen += 1) {
            const one = pump.nextRecord() catch |err| switch (err) {
                error.PeerClosed => return,
                // Through `abort` like every other refusal. A record
                // rejected at its *header* — §5.1's cap above all — is
                // refused before `handleRecord` is ever called, and
                // returning that raw is how it used to reach the peer
                // as an abrupt close rather than as the alert the table
                // names. `handshake` never had the bug because `serve`
                // wraps the whole call; this loop is its own caller and
                // has to say so. A library that refuses correctly and a
                // harness that reports the refusal as silence are
                // indistinguishable from a library that does not refuse:
                // this one line was 50 conversations of
                // `test-tls13-record-layer-limits`.
                else => return pump.abort(server, err),
            };
            // One record can carry more than one post-handshake
            // message, so every event it produced is taken before the
            // next record is read. Skipping this is not benign: the
            // extra message would be taken ahead of the following
            // record's, and `handleRecord` refuses that with
            // `EventsPending` rather than letting it lag.
            var event = server.handleRecord(one, &pump.out) catch |err| {
                return pump.abort(server, err);
            };
            // lint:unbounded-ok — each pass takes one complete message from a
            // fixed reassembly buffer that only `handleRecord` refills, and
            // `drain` answers null once none remain.
            while (true) : (event = (server.drain(&pump.out) catch |err| {
                return pump.abort(server, err);
            }) orelse break) {
                switch (event) {
                    .application_data => |bytes| {
                        if (bytes.len == 0) continue;
                        // Echo, byte for byte. A canned HTTP response answers
                        // "did anything come back" and nothing else, which is
                        // all most scripts ask — but `test-tls13-lengths`
                        // checks the *length* of the reply against what it
                        // sent, across every size from 1 to 2^14, and no
                        // fixed response can satisfy 1002 conversations that
                        // each want a different one.
                        //
                        // An error rather than an assertion, because the
                        // length is one the peer chose. No peer can reach it
                        // today: `Protector.open` caps the stripped content
                        // at §5.1's 2^14 before it ever becomes an event, and
                        // `sendApplicationData` asserts the same bound on the
                        // way back out. It is here so that the slice below is
                        // guarded by a refusal rather than by a bound proved
                        // two modules away — and if that bound ever moves,
                        // this harness answers record_overflow instead of
                        // aborting the listener mid-corpus.
                        if (bytes.len > pump.echo.len) {
                            return pump.abort(server, error.RecordOverflow);
                        }
                        // Copied out first: `bytes` points into `pump.out`,
                        // which is where the reply gets sealed, and sealing
                        // copies its content into that same buffer.
                        @memcpy(pump.echo[0..bytes.len], bytes);
                        const sealed = server.sendApplicationData(
                            pump.echo[0..bytes.len],
                            &pump.out,
                        ) catch |err| return pump.abort(server, err);
                        try pump.write(sealed);
                    },
                    .closed => {
                        // §6.1's half-close, and the one place this harness
                        // depends on `sendAlert` being callable after the
                        // peer has already closed its direction.
                        pump.write(server.sendAlert(.close_notify, &pump.out)) catch {};
                        return;
                    },
                    .send => |bytes| try pump.write(bytes),
                    .none, .connected => {},
                }
            }
        }
        return error.TooManyRecords;
    }

    /// zssl reports the error and leaves the alert to the embedder; the
    /// scripts check which alert arrives, so this table is under test
    /// just as much as the state machine is.
    fn abort(pump: *Pump, server: *ServerHandshake, err: anyerror) anyerror {
        const description = alertFor(err) orelse return err;
        pump.write(server.sendAlert(description, &pump.out)) catch {};
        return err;
    }
};

/// zssl error → RFC 8446 §6 alert. The same mapping `bogo/shim.zig`
/// carries, kept separately on purpose: two harnesses agreeing because
/// they share a table would prove less than two arriving at the same
/// answer, and tlsfuzzer checks alerts BoGo does not.
fn alertFor(err: anyerror) ?zssl.alert.Description {
    return switch (err) {
        error.UnexpectedMessage,
        error.UnknownContentType,
        error.EmptyFragment,
        error.BadInnerPlaintext,
        error.UnexpectedRecordType,
        error.TooManyEmptyRecords,
        error.TooManyKeyUpdates,
        error.TooManyWarningAlerts,
        => .unexpected_message,
        error.AuthenticationFailed => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.NotATlsRecord => .protocol_version,
        error.HandshakeFailure => .handshake_failure,
        error.MissingExtension => .missing_extension,
        error.UnsupportedExtension => .unsupported_extension,
        error.IllegalRetry,
        error.IdentityElement,
        error.IllegalKeyUpdate,
        error.IllegalCompression,
        error.PskNotLast,
        error.BadKeyShare,
        error.NonMinimalEncoding,
        error.BinderCountMismatch,
        => .illegal_parameter,
        error.MalformedAlert,
        error.BadAlert,
        error.MalformedMessage,
        error.MalformedCertificate,
        error.MalformedExtension,
        error.DuplicateExtension,
        error.SuiteOverflow,
        error.ExtensionOverflow,
        error.Truncated,
        error.TrailingBytes,
        => .decode_error,
        error.DecryptError, error.BadBinder => .decrypt_error,
        error.NoApplicationProtocol => .no_application_protocol,
        error.SequenceExhausted,
        error.RotationsExhausted,
        error.LibcryptoFailed,
        error.BufferOverflow,
        => .internal_error,
        else => null,
    };
}

fn readFile(io: Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const buffer = try arena.alloc(u8, 64 * 1024);
    var reader = file.reader(io, buffer);
    const sink = try arena.alloc(u8, 64 * 1024);
    const read_bytes = try reader.interface.readSliceShort(sink);
    assert(read_bytes >= 1);
    return sink[0..read_bytes];
}
