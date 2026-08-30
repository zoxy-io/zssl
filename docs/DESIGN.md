# zssl design

A sans-I/O TLS 1.3 protocol layer in Zig over libcrypto primitives.
Written to replace the audited `zoxy-io/ztls` fork as zoxy's TLS engine,
on zoxy's terms from the first line: TIGER_STYLE throughout, kTLS as a
design input rather than a bolt-on, and a scope cut to what a terminating
proxy needs instead of what a general TLS library carries.

§1 says what exists; §6 says what proved it. The sections in between are
the four decisions everything else follows from.

## §1 Scope

### Built

- **TLS 1.3 only** (RFC 8446) — no 1.2, no downgrade dance beyond
  reading the compatibility fields 1.3 froze. Both halves:
  `ServerHandshake` terminates, `ClientHandshake` originates. Both
  tolerate D.4's compatibility ChangeCipherSpec, bounded, and the server
  reassembles a fragmented ClientHello.
- **The three RFC 8446 suites**, over x25519, secp256r1 and secp384r1.
  The server takes whichever group the client offered a share for, in
  its own preference order (§4.2.8 leaves the choice to the server), and
  asks for the first one it holds in a HelloRetryRequest when the client
  offered none — with §4.4.1's transcript surgery. The client advertises
  all three, shares x25519, and answers a retry with the second scalar
  in `Config.retry_key_share_private`. §4.1.4's illegal shapes are
  refused and told apart: a retry that changes nothing, or names a group
  never advertised, is `IllegalRetry`; a second retry is
  `UnexpectedMessage`; a cookie-only retry is legal and re-sends the
  same share.
- **ECDSA P-256/P-384 and RSA-PSS**, signing and verification.
  rsa_pkcs1_* stays out on both sides, because §4.4.3 forbids it in
  CertificateVerify. ECDSA signs through libcrypto, with an opt-in
  RFC 6979 deterministic-nonce mode; a peer's RSA-PSS is checked through
  `std.crypto`, for the reason §2 records. What the client will accept is
  `Config.verify_schemes`, and §4.4.3 makes that list a promise rather
  than a hint: a CertificateVerify under a scheme absent from it is an
  `illegal_parameter` abort with nothing verified, told apart from a
  signature that simply failed. `ClientHandshake.peer.scheme`
  reports what the server actually used, mirroring the server's own
  `signature_scheme`. The server's signing set narrows through
  `Config.signing_schemes`, whose order wins over the key's — and which
  takes wire code points rather than an enum, so pinning a scheme the key
  cannot produce is answered with `HandshakeFailure` rather than being
  unrepresentable.
- **PSK resumption.** `psk_lookup` is the embedder seam: an opaque
  identity goes in, the PSK *and its kind* come out, and ticket sealing,
  lifetime and age policy stay the embedder's. Both kinds are accepted
  server-side — resumption and external PSKs differ by §4.2.11.2's
  binder label ("res binder" against "ext binder") — while the client
  offers resumption PSKs only, because an external one would need the
  negotiated suite from somewhere other than the PSK's length.
  A recognized identity with a bad binder aborts; an unknown one falls
  back to a full handshake, never a downgrade. `resumptionPsk` derives
  before `sendNewSessionTicket` seals (the stateless-server ordering),
  and issuance happens strictly after `connected` (the delayed-ACK
  lesson). Scope cut: psk_ke without (EC)DHE is never accepted.
- **0-RTT**, offered by the client and accepted or declined by the
  server, with §8's anti-replay checked here rather than promised by the
  embedder. Accepted bytes arrive as `Event.early_data`, never as
  `application_data`: Appendix E.5 is a warning the embedder has to act
  on, and an exhaustive switch is how it gets asked. See below.
- **SNI and ALPN** reads, with RFC 7301 selection checks client-side.
- **RFC 5705 exporters** (§7.5), on both machines: `exporter(label,
  context, out)`, available to a server from its own Finished — §2's
  0.5-RTT window included — and to a client from `connected`. Not to be
  confused with `exportKeyMaterial`, which is §4's kTLS hand-off and
  unrelated; the RFCs' names are as close as ours.
- **KeyUpdate** (§4.6.3), living once in `session_keys.zig` and shared
  by both machines: rotation resets the sequence space, and a rotation
  ceiling turns a request loop into an error rather than a spin.
- **kTLS key export** (§4).

### Not built

- **Client certificates** — no CertificateRequest on either side.
- **Coverage-guided fuzzing.** The targets exist and run once per build;
  the search does not (§6).

### Never

TLS 1.2 and earlier, renegotiation, compression, RSA and DSA key
exchange, SSLv3-era anything, post-handshake client auth, and **QUIC and
DTLS** — there is no datagram record layer and none planned. A caller
that needs these wants a different library.

**X.509 chain validation** is out too, but delegated rather than
missing: `ClientHandshake.Config.chain_verifier` shows the embedder the
peer's chain, leaf first, while the bytes are live, and its refusal
aborts the handshake. The split is possession here, identity there. It
became load-bearing exactly when predicted — when an embedder (zrk)
originated TLS to upstreams it does not control, and RFC 9525 bound that
embedder rather than this library.

### Why RSA, when ECDSA is the key to deploy

An RSA sign is ~1–2 ms where ECDSA is ~100–400 µs. That gap is why zssl
needs no worker pool and it is still the deployment advice — but it is
advice about which key an embedder *configures*, not a reason the
library should be unable to present a key the embedder already owns.
BoGo settled it: every server case it runs is handed an RSA leaf unless
the case says otherwise, so an ECDSA-only signer left the entire server
half adversarially untested. RSA keys are bounded at load to 2048..4096
bits and sign PSS with a digest-length salt under whichever of
sha256/384/512 the client offered. Deterministic nonces and RSA are
mutually exclusive and refused together at load: PSS draws a fresh salt
per signature, so the seeded-replay property cannot survive an RSA key
and is not quietly dropped.

### Why three groups, when x25519 was enough

x25519 was the only group for a long time and that was the right
default. What changed the answer is testability: the corpora that test a
*server* mostly assume secp256r1 — 45 of tlsfuzzer's 57 TLS 1.3 scripts
name it and never mention x25519 — so an x25519-only server was not
merely narrow, it was close to untestable by anything but our own
client. The same argument widened the client, where BoGo drove two dozen
retry cases no single-group client could reach.

### Why 0-RTT is in, having been out twice

§8 lets a server accept early data only with single-use tickets (§8.1)
or a strike register over recorded ClientHellos (§8.2), and either way
with a freshness check (§8.3). The old refusal said zssl could implement
none of the three, because §8.2 and §8.3 want a clock this library did
not have. That treated an absence as an invariant. CLAUDE.md's list is
no allocators, no randomness, and record caps at header parse; time was
simply a thing nobody had needed yet.

It is supplied now through `Config.now_ms`, on the same terms as
`server_random` — read from the embedder once per connection, never
measured, so a replayed simulation feeds the same number and gets the
same run. §4.6.1's ticket lifetime is the first thing it buys, and that
one stands on its own: a server MUST NOT use a ticket beyond its
lifetime, and until now zssl could only hope the lookup had checked.

The objection worth keeping was never "we lack a clock" but *acceptance
as a trust seam* — the embedder promising it did §8, zssl unable to
tell, and `return true` being at once the easiest implementation and the
insecure one. With a clock and a caller-owned strike register, §8.2 and
§8.3 stop being promises and become something this library checks, with
the embedder supplying storage exactly as it supplies `reassembly` and
`flight`. §8.1 stays the embedder's, and is the one we do not need.

So §8.2's strike register and §8.3's freshness check are
`src/anti_replay.zig`, in caller-owned storage; §4.2.10's accept path
and §4.5's EndOfEarlyData are `ServerHandshake`; §2's 0.5-RTT came with
it, because a server that reads early data wants to answer before the
client's Finished. The absence of a clock is still load-bearing in one
direction: `now_ms` is optional, and without it everything §8 needs time
for is off, so a server that never thought about time cannot accept
replayable data by accident. The shim opts in the way any embedder must,
which is what let BoGo drive the accept path; docs/BOGO.md finding 18 is
what that cost and what it caught.

Rejecting 0-RTT was always the separable half and came first: a server
that declines early data still has to skip past what the client already
sent, because §5 gives it no way to say no in time (docs/BOGO.md
finding 14).

Appendix E.5 wants the application to tell early data from ordinary
data, and it can: accepted 0-RTT arrives as `Event.early_data`, never as
`application_data`. A separate variant rather than a flag on the
existing one, because a bool is a thing an embedder forgets to read and
an exhaustive switch is not. One that has no 0-RTT profile writes that
arm as an error — the honest answer, and one line.

## §2 The trust split

The protocol state machine — where TLS CVEs live — is Zig in this tree.
Constant-time primitives — AEAD, X25519, ECDSA — are libcrypto's, the
most-watched assembly on earth. HKDF, HMAC, and the transcript hash are
pure Zig over `std.crypto`: hashing public-length data is not where the
sharp edges are, and this is the same line ztls drew and zoxy audited.
So is verifying a peer's **RSA-PSS** — a public-length message against a
public key is not where the constant-time argument bites either.
ECDSA verification sat on the same side of the line until `bench/` priced
the difference and moved it; RSA-PSS has not been priced, and moving it
on the strength of another primitive's number would be guessing.

**One backend, on purpose.** OpenSSL is the only libcrypto family member
with `CRYPTO_set_mem_functions`, and that hook is what makes a
zero-allocation budget over a C library a checkable property instead of
a hope (`src/crypto/mem_hooks.zig`). BoringSSL and AWS-LC removed the
API, so a backend for them could never satisfy §3 — carrying their
bindings anyway is how ztls spent ~660 lines saying "unsupported". The
pin is `zoxy-io/openssl` 3.5.7 (LTS to 2030), the same commit zoxy
links, because the embedder's binary must contain exactly one libcrypto.

The C surface is two files: `src/crypto/c.zig` (the single `@cImport`)
and `src/crypto/backend_openssl.zig` (every call site). Nothing behind
the boundary parses attacker bytes; callers hand in framed slices with
asserted lengths.

## §3 Memory

Zero allocation, full stop — not "after startup", because zssl has no
startup: every buffer is caller-owned and every struct is fixed-size.
The embedder owns startup, installs the `mem_hooks` triple before first
libcrypto use, and sizes the fixed heap that libcrypto's own internals
(EVP contexts, PKEY objects) land in. zoxy's measured budget is ~4.9 KiB
of libcrypto heap per session engine plus a 2 MiB base; zssl's job is to
keep the per-record path free of *any* allocation: AEAD contexts are
created once per traffic key (`AeadKey.init`) and reused per record; the
X25519 `EVP_PKEY` objects live only inside one handshake's key
agreement.

## §4 kTLS is a design input

The reason this library exists rather than a fifth fork commit. Once the
handshake completes, the record layer should be able to move into the
kernel (`setsockopt(SOL_TLS)`), leaving userspace record protection as
the fallback path rather than the only path.

That requires exactly one thing of the library's shape: traffic keys,
static IVs, and sequence numbers must be *first-class, exportable state*
— never hidden inside an opaque session. `src/ktls.zig` defines the
kernel UAPI payloads and packs them from `KeyMaterial`; `Protector`
(`src/protect.zig`) carries `static_iv` and `sequence` as plain fields
so the hand-over is a read, not an excavation.

The switchover contract is *tickets first, then export both directions
after any KeyUpdate, then stop feeding the machine* —
`exportKeyMaterial` reflects the current generation, so a hand-over that
races a rotation exports the keys the peer is actually using. The
syscalls are the embedder's; so is reading post-handshake messages back
out of CMSG once the kernel owns the stream.

## §5 Records

Framing caps are enforced before a record reaches a buffer, per content
type: §5.1's 2^14 for plaintext records and §5.2's 2^14+256 for protected
ones at header parse (`record.parseHeader`), and §5.4's 2^14+1 for the
inner plaintext in `Protector.open` — which is where it has to live,
because `parseHeader` does not know the suite whose tag length the inner
length is derived from. The §5.4 one was described here before it
existed anywhere else; see BoGo finding 3.

What is *not* enforced there is `legacy_record_version`'s minor byte:
§5.1 calls the field deprecated and says it "MUST be ignored for all
purposes", and enforcing it refused real clients whose initial
ClientHello says 0x0301 (BoGo finding 4). The major byte is still
checked, as framing rather than version — `0xffff` is not a TLS record.
This is a direct lesson from the ztls defect queue, where the record
layer admitted oversized plaintext and the embedder compensated above
the API.

`Protector` is one direction under one traffic key: AEAD contexts,
static IV, sequence. The §5.5 sequence bound (2^24 records, the
AES-GCM-conservative figure applied to every suite) is an error, not a
wrap. zssl never writes padding; it strips peers' padding per §5.4, caps
the inner plaintext it was handed at §5.4's 2^14+1 before doing any AEAD
work, and caps what is left after stripping at §5.1's 2^14. Both halves
matter: a peer can spend the whole budget on padding.

## §6 What proved it

Every claim in §1 is held up by at least one oracle that shares no code
with this tree.

**RFC 8448 replay.** The RFC's traced bytes, reproduced exactly: §3's
full handshake down to the record keys, and §4's binder chain,
truncation arithmetic, PSK ServerHello, PSK-mixed ladder and 0-RTT
branch of the schedule. The vectors are *generated* from the RFC text by
`scripts/extract_rfc8448.py` — hand-copied hex is how vector tests rot.

**`std.crypto.tls.Client`.** A full in-memory handshake against std's
own client: no shared code, std's X.509 and ECDSA judging our
Certificate and CertificateVerify.

**Real OpenSSL** — `zig build interop`, genuine libssl over real
sockets. Five legs: `openssl s_client` against our server over a P-256
leaf, over a P-384 one, and through a HelloRetryRequest asserted to have
happened rather than inferred from the group it landed on; then our
client against `openssl s_server` over ECDSA and over RSA, both
exercising the `chain_verifier` seam. Application bytes cross in every
leg, because a handshake that completes but cannot carry traffic has
proven the easier half.

**BoGo** — `zig build bogo`, BoringSSL's hostile-peer runner at a pinned
commit, asking what we *refuse* and checking *which* alert we send. It
found three bugs on its first run: a client that never advertised
`psk_key_exchange_modes`, and so could never be given a ticket by a
conforming server; a mid-handshake alert that preceded D.4's
compatibility record; and a reachable assertion on flight size. Its
ledger is `bogo/config.json`, where every entry carries a reason and
`grep 'OPEN GAP'` is the count of what is actually open. docs/BOGO.md
carries the numbers and the queue.

**tlsfuzzer** (`zig build tlsfuzzer`), a Python client over tlslite-ng
driving our server, and **TLS-Anvil** (`zig build tlsanvil`), a corpus
derived from the RFCs rather than from any implementation, against the
same harness. Both hold a passing count against a floor, so a quiet
suppression stops the build. docs/TLSFUZZER.md, docs/TLSANVIL.md.

**Fuzzing.** Nine targets over every parser and both state machines,
asserting the one property that matters for a library whose assertions
are claims about *our* state: arbitrary peer bytes produce a value or an
error, never a panic. `zig build test` runs each once over its corpus,
and that is what CI gates on. The coverage-guided search (`--fuzz`) is
blocked on a toolchain bug — 0.16.0's own fuzzing test runner fails to
compile (`compiler/test_runner.zig:566`, two `StackTrace` types crossed)
— reproduced identically in the zoxy tree, so it is the pinned compiler
and not this library.

**In-tree scenarios**, where both production machines run end to end:
handshake, resumption, KeyUpdate in both directions with kTLS exports
agreeing across machines at every generation, the same pair driven
*through* a retry, and 0-RTT offered, accepted, declined, and replayed
against a strike register that refuses it. Driving a retry in-tree
needed `ServerHandshake.Config.groups` — with x25519 in the list the
server takes the share our client always sends and never retries, so
until the preference could be narrowed that path rested on BoGo alone.

Deliberately absent: a differential against ztls. It moves to zoxy's
engine swap, where the two run side by side and a disagreement is
diagnosable against a live proxy.

## §7 Testing stance

Three kinds of evidence, and anything new carries all three: replay
against an implementation sharing no code, a differential against a
second implementation for the inputs no trace covers, and negative-space
tests — tampered tags, skewed sequences, truncation at every prefix,
forbidden grammar. An oracle that only ever sees well-formed input is
measuring the easy half.
