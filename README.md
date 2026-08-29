# zssl

[![test](https://github.com/zoxy-io/zssl/actions/workflows/test.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/test.yml)
[![fmt](https://github.com/zoxy-io/zssl/actions/workflows/fmt.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/fmt.yml)
[![coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fzoxy-io%2Fzssl%2Fbadges%2Fcoverage.json)](https://github.com/zoxy-io/zssl/actions/workflows/coverage.yml)

A sans-I/O TLS 1.3 library in Zig, over libcrypto primitives.

zssl implements the protocol — records, the key schedule, both handshake
state machines, resumption, KeyUpdate — in auditable Zig, and calls
libcrypto only for the constant-time primitives (AEAD, X25519, ECDSA and
RSA-PSS signing); checking a *peer's* signature is `std.crypto`'s. It owns no
sockets, no threads, and no memory: you feed it whole TLS records and
transmit whatever it hands back.

```zig
var event = try server.handleRecord(wire_record, &out);
// lint:unbounded-ok — `drain` answers null once the record's
// messages are used up.
while (true) {
    switch (event) {
        .send => |bytes| try socket.writeAll(bytes),
        .application_data => |plaintext| try onRequest(plaintext),
        .connected, .closed, .none => {},
    }
    event = try server.drain(&out) orelse break;
}
```

One record can carry more than one message, so `drain` hands back what
is left until it answers null. Skipping it is caught rather than left to
lag: the next `handleRecord` answers `EventsPending`.

That shape is the whole interface, and it is what makes zssl usable from
an `io_uring` event loop, a thread-per-connection server, or a
deterministic simulator with a virtual clock — none of which it needs to
know about.

**Status: prototype.** It is exercised hard (see [Testing](#testing)),
interoperates with OpenSSL and `std.crypto.tls` in both directions, and
both halves run under BoringSSL's adversarial BoGo runner, which has
found real defects — a remote panic on a garbage certificate among them —
and leaves nine findings still on the ledger, all recorded in
[docs/BOGO.md](docs/BOGO.md). The server half also runs under tlsfuzzer,
which has found three ([docs/TLSFUZZER.md](docs/TLSFUZZER.md)). It has had
no external audit. Don't put it in front of anything you care about yet.

## Why

Most TLS libraries hand you a socket-shaped object and own the loop. If
you are writing a proxy, that costs you the two things you needed most:

- **Nothing is hidden from the event loop.** No callbacks into a library
  that might block, no internal buffering you cannot size.
- **kTLS is a first-class hand-off, not a fight.** Traffic keys, IVs and
  record sequence numbers are exportable state
  (`exportKeyMaterial`), so moving the record layer into the kernel is a
  read rather than an excavation.

Two properties fall out of the design and are enforced by the tests:

- **Zero allocation.** Not "after startup" — at all. Every buffer is
  caller-owned or a fixed array. `std.mem.Allocator` appears nowhere in
  the library.
- **Zero randomness.** zssl never calls an RNG. Handshake randoms and
  ephemeral keys arrive through `Config`, which is what lets a seeded
  simulation replay a session byte for byte.

## Install

```sh
zig fetch --save git+https://github.com/zoxy-io/zssl
```

```zig
const zssl_dependency = b.dependency("zssl", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zssl", zssl_dependency.module("zssl"));
```

libcrypto is built from source by Zig for your target — nothing is
resolved from the host — so cross-compilation works out of the box.

## Usage

### Terminating TLS

Load credentials once; everything after is per-connection.

```zig
const zssl = @import("zssl");

var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
var credentials = try zssl.Credentials.load(cert_pem, key_pem, &chain_storage, false);
defer credentials.deinit();
```

Each connection gets a handshake, two caller-owned buffers, and 64 bytes
of entropy you supply:

```zig
var reassembly: [16 * 1024]u8 = undefined;
var flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;

var entropy: [80]u8 = undefined;
io.random(&entropy); // your `std.Io` — zssl never calls an RNG itself

var server = zssl.ServerHandshake.init(&.{
    .credentials = &credentials,
    .server_random = entropy[0..32].*,
    // 48 bytes: enough scalar for the largest group zssl offers.
    .key_share_private = entropy[32..80].*,
    .alpn = "http/1.1",
    .reassembly = &reassembly,
    .flight = &flight,
});
defer server.deinit();
```

Then drive it with whole records. `zssl.record_buffer.RecordBuffer` turns
a byte stream into those, policing the RFC 8446 §5 length caps as bytes
arrive:

```zig
var out: [zssl.ServerHandshake.out_bytes_min]u8 = undefined;

stream: while (try records.next()) |wire_record| {
    // One record can hold several messages — a NewSessionTicket packed
    // with a KeyUpdate is what Go and OpenSSL emit — so take events
    // until `drain` answers null. Each borrows `out`, so act on one
    // before asking for the next.
    var event = try server.handleRecord(wire_record, &out);
    // lint:unbounded-ok — each pass takes one complete message from a
    // fixed reassembly buffer that only `handleRecord` refills, and
    // `drain` answers null once none remain.
    while (true) {
        switch (event) {
            // Handshake bytes to put on the wire.
            .send => |bytes| try socket.writeAll(bytes),
            // The session is up; app data may now flow both ways.
            .connected => {},
            // Decrypted application bytes, valid until the next call.
            .application_data => |plaintext| try onRequest(plaintext),
            // The peer sent close_notify. The label is not decoration —
            // an unlabelled break would leave only the drain loop.
            .closed => break :stream,
            // A record that advanced nothing — a fragment, or a CCS.
            .none => {},
        }
        event = try server.drain(&out) orelse break;
    }
}

const reply = try server.sendApplicationData("HTTP/1.1 200 OK\r\n\r\n", &out);
try socket.writeAll(reply);
```

On any error the machine is `failed` and must not be fed again — close
the connection. That is the whole contract.

### Originating TLS

The client half has the same shape; `start` produces the ClientHello, and
the `connected` event carries the flight to send:

```zig
var reassembly: [16 * 1024]u8 = undefined;
var client = zssl.ClientHandshake.init(&.{
    .client_random = entropy[0..32].*,
    .x25519_private = entropy[32..64].*,
    .server_name = "origin.internal",
    .alpn_protocols = &.{ "h2", "http/1.1" },
    .certificate_policy = .leaf_signature,
    .chain_verifier = .{ .context = &trust, .verify = &yourChainCheck },
    .reassembly = &reassembly,
});
defer client.deinit();

try socket.writeAll(client.start(&out));

stream: while (try records.next()) |wire_record| {
    var event = try client.handleRecord(wire_record, &out);
    // lint:unbounded-ok — each pass takes one complete message from a
    // fixed reassembly buffer that only `handleRecord` refills, and
    // `drain` answers null once none remain.
    while (true) {
        switch (event) {
            .send, .connected => |bytes| try socket.writeAll(bytes),
            .application_data => |plaintext| try onResponse(plaintext),
            .ticket => |ticket| try store(ticket),
            .closed => break :stream,
            .none => {},
        }
        event = try client.drain(&out) orelse break;
    }
}
```

`alpn_protocols` is offered in preference order; `client.alpnSelected()`
reports what the server took, or null if it took nothing — an answer
rather than an error, because a server that ignores an `h2` offer is
something a client should report, not die on.

Certificate handling is split in two, on purpose.

**Possession** is zssl's: `.leaf_signature` verifies the server's
CertificateVerify against the key its leaf presents — ECDSA P-256/P-384
or RSA-PSS, since an originating client does not choose what its
upstreams present. `.insecure_no_verification` skips it entirely and
says so in its name.

**Identity** is yours: `chain_verifier` is shown the peer's chain, leaf
first, while the bytes are still live, and returning false aborts the
handshake before the leaf's signature is even checked. **Chain building
and RFC 9525 name matching are yours to do**, deliberately, because a
proxy's trust decisions belong to the proxy — `std.crypto.Certificate`
has the pieces. Configure no verifier and zssl proves possession alone,
which authenticates the key and says nothing about who holds it.

### Resumption and kTLS

After `connected`, a server can issue tickets and either side can rotate
keys or hand the connection to the kernel:

```zig
// Derive the PSK first, seal your own ticket around it, then send.
var psk_buffer: [zssl.cipher_suite.hash_bytes_max]u8 = undefined;
const psk = server.resumptionPsk(&nonce, &psk_buffer);
const sealed = try server.sendNewSessionTicket(&.{
    .lifetime_s = 3600,
    .age_add = age_add,
    .ticket_nonce = &nonce,
    .ticket = your_sealed_ticket,
}, &out);

// RFC 8446 §4.6.3 rekey, and the kTLS hand-off.
const update = try server.sendKeyUpdate(true, &out);
const keys = server.exportKeyMaterial(.transmit);
```

Ticket sealing, lifetime and age policy stay with you: zssl takes an
opaque identity through `Config.psk_lookup` and answers with the PSK,
then verifies the binder itself. A recognised identity with a bad binder
aborts the handshake rather than falling back — a replayed ticket is
refused, not downgraded.

## Scope

**In:** TLS 1.3 (RFC 8446), the three standard cipher suites, key
exchange over x25519, secp256r1 and secp384r1 (server side; the client
offers x25519 alone), ECDSA P-256/P-384 and RSA-PSS signing and
verification, SNI, ALPN,
HelloRetryRequest (the server issues it; the client refuses it
structurally, holding keys for one group), PSK resumption with
server-side tickets, KeyUpdate, and kTLS key export.

ECDSA is still the key to *deploy* — an RSA sign is a millisecond where
ECDSA is a few hundred microseconds, and that gap is why zssl needs no
worker pool. RSA is supported because a library should be able to
present a key its embedder already owns, not because it is the one to
choose. RSA keys are bounded at 2048..4096 bits and refused at load
outside it.

**Out, permanently:** TLS 1.2 and earlier, renegotiation, compression,
RSA and DSA *key exchange*, rsa_pkcs1_* signatures (§4.4.3 forbids them
in CertificateVerify). A caller that needs these wants a different
library.

**Out, for now:** 0-RTT (a replay-analysis decision, not a convenience),
X.509 chain validation (the embedder's, through `chain_verifier`),
client certificates, and QUIC.

Everything above is argued in [docs/DESIGN.md](docs/DESIGN.md) §1.

## Testing

Seven kinds of evidence, in rough order of how much they are worth. Each is
its own CI workflow, so they run in parallel and fail separately.

| Oracle | Status | Details |
| --- | --- | --- |
| [**BoGo**](docs/BOGO.md) | [![bogo](https://github.com/zoxy-io/zssl/actions/workflows/bogo.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/bogo.yml)<br>[![bogo passing](https://img.shields.io/badge/bogo-278%20passing-brightgreen)](docs/BOGO.md)<br>[![bogo declined](https://img.shields.io/badge/bogo-6918%20declined-lightgrey)](docs/BOGO.md#the-three-numbers) | Hostile-peer corpus; checks *which* alert we send |
| [**tlsfuzzer**](docs/TLSFUZZER.md) | [![tlsfuzzer](https://github.com/zoxy-io/zssl/actions/workflows/tlsfuzzer.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/tlsfuzzer.yml)<br>[![tlsfuzzer](https://img.shields.io/badge/tlsfuzzer-16%2F57%20scripts-yellow)](docs/TLSFUZZER.md) | A third implementation, driving our *server* |
| [**TLS-Anvil**](docs/TLSANVIL.md) | [![tlsanvil](https://github.com/zoxy-io/zssl/actions/workflows/tlsanvil.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/tlsanvil.yml)<br>[![tlsanvil passing](https://img.shields.io/badge/tls--anvil-115%20passing-brightgreen)](docs/TLSANVIL.md)<br>[![tlsanvil declined](https://img.shields.io/badge/tls--anvil-321%20declined-lightgrey)](docs/TLSANVIL.md#it-scopes-itself) | A corpus derived from the RFCs, not an implementation |
| [**RFC 8448**](src/rfc8448_test.zig) | [![rfc8448](https://github.com/zoxy-io/zssl/actions/workflows/rfc8448.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/rfc8448.yml) | The RFC's traced bytes, reproduced exactly |
| [**OpenSSL**](interop/main.zig) | [![interop](https://github.com/zoxy-io/zssl/actions/workflows/interop.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/interop.yml) | Three legs against a real `openssl` binary |
| [**`std.crypto.tls`**](src/std_interop_test.zig) | [![std.crypto.tls](https://github.com/zoxy-io/zssl/actions/workflows/std-interop.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/std-interop.yml) | A second stack, in memory, both directions |
| [**Fuzzing**](src/fuzz_test.zig) | [![fuzz](https://github.com/zoxy-io/zssl/actions/workflows/fuzz.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/fuzz.yml) | Nine targets: a value or an error, never a panic |

Plus directed tests for what only breaks under adversity — fragmented
ClientHellos, tampered Finished messages, corrupted binders, inverted
flights, sequence exhaustion.

The gaps, stated plainly. All three adversarial gates decline far more
than they run: BoGo never ran 6918 of its cases, tlsfuzzer runs 16
scripts of 57, and 321 of TLS-Anvil's 437 tests opt out against a
TLS 1.3-only server. That is why each carries a second, counted badge
rather than a bare pass mark, and why each holds its passing count
against a floor, so a regression or a quiet suppression stops the build.
Nine findings sit on BoGo's ledger, tlsfuzzer's 41 declines are all
triaged and two of them stand on open findings, and TLS-Anvil has two
open failures it refuses to suppress; the three documents name every one,
with a reason.

## Development

Most of the gates below shell out to something Zig does not bring:
`interop` to a real `openssl` binary, `bogo` to a Go toolchain,
`tlsfuzzer` to a python3, both of those to `git` for their pinned
checkouts, `tlsanvil` to a Docker daemon, and `coverage` to kcov. Each
degrades to a readable SKIP when its tool is missing — and a SKIP is not
a failure, so an incomplete toolchain turns gates off quietly.
[devenv](https://devenv.sh) supplies every one of them that is a binary:
install it alongside [direnv](https://direnv.net), run `direnv allow`,
and the pinned shell loads on `cd`. Without direnv, `devenv shell` does
the same by hand. The Docker daemon TLS-Anvil needs is yours to run.

```sh
zig build test                          # the suite
zig build test -Doptimize=ReleaseSafe   # the mode releases ship
zig build interop                       # against a real openssl binary
zig build bogo                          # against BoringSSL's BoGo runner
zig build tlsfuzzer                     # against tlsfuzzer's scripts
zig build tlsanvil                      # against TLS-Anvil's RFC-derived corpus
zig build tlsfuzzer-server -- --port 4433   # that server alone, to hand-drive
zig build coverage                      # line coverage, needs kcov (Linux)
zig fmt --check src interop bogo tlsanvil tlsfuzzer scripts build.zig build.zig.zon
```

RFC 8448 vectors are generated, never transcribed:
`scripts/extract_rfc8448.py` parses the RFC text into
`src/rfc8448_vectors.zig`. Regenerate rather than hand-editing.

[docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) is the style contract the tree
is held to.

## License

zssl is [MIT](LICENSE) © 2026 Vsevolod Strukchinsky.

Two things travel with it under other terms:

- **OpenSSL** (Apache-2.0) is compiled into any binary that links zssl,
  so that binary has to carry Apache-2.0's notice and attribution. This
  is an obligation on whoever ships the binary, not on zssl's source.
- **`src/rfc8448_vectors.zig`** is generated from the text of RFC 8448,
  which is IETF Trust material. The generator is in `scripts/`, so the
  provenance of every byte is reproducible rather than asserted.
