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

const Reply = enum { echo, http };

/// What `http` mode answers with once a request is complete. Its content
/// is irrelevant to every script that asks for it — they check that
/// *something* came back, once — so this is the shortest well-formed
/// thing that says so.
const http_response = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";

const Options = struct {
    port: u16 = 4433,
    cert_path: []const u8 = "src/testdata/cert.pem",
    key_path: []const u8 = "src/testdata/key.pem",
    alpn: ?[]const u8 = null,
    /// NewSessionTickets to issue per connection. Zero is a legitimate
    /// configuration and some scripts ask for exactly that.
    tickets: u8 = 1,
    /// An out-of-band PSK, as hex, and the identity it answers to.
    /// `test-tls13-psk_dhe_ke` is written against a server that has one:
    /// every conversation it runs offers an external identity, and a
    /// server with none can only answer handshake_failure, which is the
    /// fixture reporting on itself rather than on us.
    ///
    /// Hex because that is the form the script's own `--psk` takes, so
    /// the two sides are copied from one place. Null leaves `psk_lookup`
    /// answering resumption identities alone.
    psk: ?[]const u8 = null,
    psk_identity: []const u8 = "test",
    /// How application data is answered. `echo` replies to the first
    /// record of each run byte for byte, which is what
    /// `test-tls13-lengths` measures; `http` stays silent until the
    /// request is complete and then answers once, which is what the
    /// scripts written against `s_server -www` expect. Neither can
    /// serve the other's scripts, so the gate runs an instance of each.
    reply: Reply = .echo,
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

    var external_storage: [cipher_suite.hash_bytes_max]u8 = undefined;
    var store: TicketStore = .{};
    if (options.psk) |hex| {
        // Refused here rather than shrugged at: a harness that quietly
        // ran without the key it was told to use would fail the script
        // for a reason that is not the library's, which is the failure
        // mode two leaves already exist to avoid.
        if (hex.len % 2 != 0) return error.BadFlagValue;
        if (hex.len / 2 > external_storage.len) return error.BadFlagValue;
        if (hex.len == 0) return error.BadFlagValue;
        const secret = external_storage[0 .. hex.len / 2];
        _ = std.fmt.hexToBytes(secret, hex) catch return error.BadFlagValue;
        store.external = secret;
        store.external_identity = options.psk_identity;
    }
    var served: u64 = 0;
    while (true) : (served += 1) {
        // Named members, not the whole set. TIGER_STYLE calls this out by
        // incident: a `while (true) … catch continue` met a persistently
        // full heap and spun at 100% CPU forever, because the error that
        // would have shed load never came back. A connection that fails
        // to arrive is retryable; a listener that cannot accept at all is
        // not, and has to propagate on the first occurrence.
        const stream = listener.accept(io) catch |err| switch (err) {
            // Retryable, and all four are about *this* connection: the
            // peer went away before the accept completed, a firewall
            // refused it, its protocol handshake failed, or there was
            // nothing pending. The next script's connection is
            // unaffected, so continuing is right.
            error.ConnectionAborted,
            error.BlockedByFirewall,
            error.ProtocolFailure,
            error.WouldBlock,
            => continue,
            // Everything else is terminal and must propagate on the
            // first occurrence. `ProcessFdQuotaExceeded` and
            // `SystemFdQuotaExceeded` are precisely the condition
            // TIGER_STYLE's #222 describes: retrying a persistently
            // exhausted resource changes nothing and burns the CPU the
            // process needs to recover. `Canceled` is the watchdog
            // asking us to stop, which a `continue` would ignore.
            else => return err,
        };
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
        } else if (std.mem.eql(u8, argument, "--psk")) {
            options.psk = value;
        } else if (std.mem.eql(u8, argument, "--psk-iden")) {
            options.psk_identity = value;
        } else if (std.mem.eql(u8, argument, "--reply")) {
            if (std.mem.eql(u8, value, "echo")) {
                options.reply = .echo;
            } else if (std.mem.eql(u8, value, "http")) {
                options.reply = .http;
            } else return error.BadFlagValue;
        } else {
            return error.UnknownFlag;
        }
    }
    assert(options.port >= 1);
    return options;
}

/// The embedder's PSK state: the ticket last issued, kept across
/// connections so the resumption scripts have something to come back
/// with, and an out-of-band key when `--psk` configured one.
///
/// Both answer through the same seam, which is the point of
/// `ServerHandshake.Psk` carrying a kind — §4.2.11.2 derives the binder
/// under a different label for each, and only this side knows which.
const TicketStore = struct {
    psk: [cipher_suite.hash_bytes_max]u8 = undefined,
    psk_bytes: u8 = 0,
    /// `--psk`/`--psk-iden`, already decoded from hex.
    external: ?[]const u8 = null,
    external_identity: []const u8 = "",

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age; // Age policy is the embedder's; this one has none.
        const self: *TicketStore = @ptrCast(@alignCast(context));
        // The external key first: it is configured once and never
        // changes, where the ticket slot holds whatever the last
        // connection left behind.
        if (self.external) |secret| {
            if (std.mem.eql(u8, identity, self.external_identity)) {
                assert(secret.len <= psk_out.len);
                @memcpy(psk_out[0..secret.len], secret);
                return .{ .psk_bytes = @intCast(secret.len), .kind = .external };
            }
        }
        if (self.psk_bytes == 0) return null;
        if (!std.mem.eql(u8, identity, ticket_identity)) return null;
        psk_out.* = self.psk;
        return .{ .psk_bytes = self.psk_bytes, .kind = .resumption };
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

    try pump.converse(&server, options.reply);
}

const Pump = struct {
    io: Io,
    stream: Io.net.Stream,
    records: zssl.record_buffer.RecordBuffer,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    read_buffer: [4 * record.wire_record_bytes_max]u8,
    write_buffer: [4 * record.wire_record_bytes_max]u8,
    storage: [4 * record.wire_record_bytes_max]u8,
    out: [4 * record.wire_record_bytes_max]u8,
    /// Where a record's plaintext is held while its echo is sealed back
    /// into `out`, and — in `http` mode — where the request accumulates
    /// until its terminator arrives. §5.1's cap, because that is the
    /// most `sendApplicationData` accepts in one record, and because a
    /// request longer than one record's worth is past what any script
    /// here sends.
    ///
    /// The two uses never interleave: `reply` is fixed from argv for the
    /// life of the process, so an instance either echoes or accumulates
    /// and never does both.
    echo: [record.plaintext_bytes_max]u8,

    fn init(pump: *Pump, io: Io, stream: Io.net.Stream) void {
        pump.io = io;
        pump.stream = stream;
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
            if (try server.handleRecord(one, &pump.out)) |ready| switch (ready) {
                .send => |bytes| try pump.write(bytes),
                .connected => {},
                .closed => return error.PeerClosedDuringHandshake,
                // This harness never supplies `now_ms` or a strike
                // register, so §8's gates are all off and early data is
                // skipped rather than accepted — `early_data` here would
                // mean the library accepted 0-RTT nobody opted into.
                .early_data, .application_data => return error.UnexpectedEvent,
            };
        }
    }

    /// Post-handshake: answer application data, and answer a close_notify
    /// with our own — `ExpectAlert` in the scripts is waiting for it.
    fn converse(pump: *Pump, server: *ServerHandshake, reply: Reply) !void {
        var records_seen: u32 = 0;
        // One reply per *run* of application-data records, where any
        // other record starts a new run.
        //
        // Echoing every record is what `test-tls13-lengths` needs — 1002
        // conversations, each sending one record and checking the reply
        // is exactly as long. Several other scripts split one request
        // across three records and then wait for a single response, and
        // read our second echo where they expected an alert or a ticket.
        // Answering the first of a run satisfies both: `lengths` sends
        // one record, so its run is one record long.
        //
        // A run has to end on a non-application record rather than on a
        // reply, because `test-tls13-keyupdate` sends a request, a
        // KeyUpdate, and a second request, and expects an answer to
        // each. Resetting on the KeyUpdate is what keeps that a two-reply
        // conversation while the three-record ones stay at one.
        //
        // A zero-length application record does not end a run: §5.4
        // makes it legal application data, the scripts interleave them
        // with the fragments on purpose, and treating one as a boundary
        // would echo the fragment behind it.
        var echoed_this_run = false;
        // Bytes of the request seen so far, in `http` mode only.
        var request_bytes: usize = 0;
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
            var data_this_record = false;
            while (event) |ready| : (event = server.drain(&pump.out) catch |err| {
                return pump.abort(server, err);
            }) {
                switch (ready) {
                    .application_data => |bytes| {
                        data_this_record = true;
                        if (bytes.len == 0) continue;
                        if (reply == .http) {
                            // Silence until the request is complete, then
                            // one canned response — `s_server -www`'s
                            // shape, and the only one that satisfies a
                            // script which sends `GET` and ` / HTTP/1.0`
                            // in separate records and expects a single
                            // reply, or one that sends an incomplete
                            // request and expects nothing but the alert
                            // its next record earns.
                            if (request_bytes + bytes.len > pump.echo.len) {
                                return pump.abort(server, error.RecordOverflow);
                            }
                            @memcpy(pump.echo[request_bytes..][0..bytes.len], bytes);
                            request_bytes += bytes.len;
                            // What the refusal above just proved, said
                            // where the next reader needs it: the slice
                            // taken below is in bounds.
                            assert(request_bytes <= pump.echo.len);
                            if (std.mem.indexOf(u8, pump.echo[0..request_bytes], "\r\n\r\n") == null) {
                                continue;
                            }
                            request_bytes = 0;
                            const sealed = server.sendApplicationData(
                                http_response,
                                &pump.out,
                            ) catch |err| return pump.abort(server, err);
                            try pump.write(sealed);
                            continue;
                        }
                        if (echoed_this_run) continue;
                        echoed_this_run = true;
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
                    .connected => {},
                    // Unreachable twice over: §8's gates are off in this
                    // harness, so no early data is ever accepted, and
                    // this loop runs past `connected` where none could
                    // arrive anyway. An error rather than a silent arm,
                    // because either way round it would mean the machine
                    // handed us 0-RTT nobody asked for.
                    .early_data => return error.UnexpectedEvent,
                }
            }
            // A record that delivered no application data ends the run,
            // and the reply budget below is per run. This used to be a
            // `.none` arm in the switch above; null does not reach a
            // switch, so it moved out here — where it covers the record
            // that produced nothing *and* the message consumed in
            // silence, which the arm never saw separately anyway. One
            // application_data record yields at most one such event and
            // a handshake record yields none, so the test is exact.
            if (!data_this_record) echoed_this_run = false;
        }
        return error.TooManyRecords;
    }

    /// zssl reports the error and leaves the alert to the embedder; the
    /// scripts check which alert arrives, so this table is under test
    /// just as much as the state machine is.
    /// Send the alert this error deserves, then close in the order that
    /// lets the peer actually read it.
    ///
    /// Writing the alert is not enough, and this cost a day to see. Most
    /// of these conversations put more bytes on the wire behind the one
    /// we refuse — `test-tls13-keyupdate` sends its bad KeyUpdate and an
    /// HTTP request in the same breath — so when we close, those bytes
    /// are still sitting unread in our receive queue. A `close()` with
    /// unread data does not send FIN: it sends **RST**, and an RST tells
    /// the peer to discard its receive buffer, including the alert we
    /// just wrote. tlsfuzzer reports that as "Unexpected closure from
    /// peer", which reads exactly like a server that answered nothing.
    ///
    /// Whether the peer's trailing bytes had arrived yet is a race, so
    /// the same conversation passed or failed run to run and the script
    /// looked flaky rather than broken — 48 to 62 of 62 on an unmodified
    /// binary, and it was never the connection budget the ledger used to
    /// blame.
    ///
    /// So: half-close first, which flushes the alert and sends FIN, then
    /// read what the peer had in flight until it closes its own side.
    /// The drain is bounded because a peer is entitled to never close —
    /// `connection-abort` has 150 conversations that do exactly that,
    /// and the watchdog is the backstop for the rest.
    fn abort(pump: *Pump, server: *ServerHandshake, err: anyerror) anyerror {
        const description = alertFor(err) orelse return err;
        pump.write(server.sendAlert(description, &pump.out)) catch {};
        pump.drainBeforeClose();
        return err;
    }

    /// Reads left before we stop waiting for a peer to close its side.
    /// Small: the peer we are talking to has just been sent a fatal
    /// alert and every well-behaved one closes immediately.
    const drain_reads_max: u8 = 16;

    fn drainBeforeClose(pump: *Pump) void {
        pump.stream.shutdown(pump.io, .send) catch return;
        var reads: u8 = 0;
        while (reads < drain_reads_max) : (reads += 1) {
            pump.reader.interface.fill(1) catch return; // EOF, or the watchdog.
            const available = pump.reader.interface.buffered();
            if (available.len == 0) return;
            pump.reader.interface.toss(available.len);
        }
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
        // §4.2.10's two early-data ceilings answer the same way, and
        // BoringSSL sends this for both (`SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA`
        // in `ssl/tls_record.cc`, `SSL_R_TOO_MUCH_READ_EARLY_DATA` in
        // `ssl/s3_pkt.cc`): one bounds data we declined and never keyed,
        // the other data we did.
        error.TooMuchSkippedEarlyData,
        error.TooMuchEarlyData,
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
