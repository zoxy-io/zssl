# BoGo — wired

BoGo is BoringSSL's adversarial TLS test runner: a Go program that plays
a deliberately hostile peer and drives an implementation through some
thousands of cases, most of which are things a correct stack must
*refuse*. It is the highest-value item on zssl's assurance ladder,
because every other oracle in the tree tests what we accept.

It now runs: `zig build bogo`.

```
bogo: 133 passed, 0 failed, 7310 declined by the shim (89), floor 133
bogo: PASS
```

Those three numbers are the honest statement of where the ladder stops,
and the rest of this file is what they mean.

## How it is wired

- **`bogo/shim.zig`** — the binary BoGo spawns per case. It connects to
  the runner on loopback, announces its `-shim-id` as a little-endian
  u64, and drives `ClientHandshake` or `ServerHandshake` over the socket
  (`ssl/test/PORTING.md` is the contract). Two things live there rather
  than in the library, on purpose: the **error → alert table**, because
  zssl returns errors and leaves the decision to alert with the embedder,
  and the **ticket store**, because sealing and age policy are the
  embedder's by design (slice 3).
- **`bogo/run.zig`** — the gate. Fetches the pinned BoringSSL commit into
  `zig-out/bogo/` (blobless, by SHA, so a run is reproducible), builds
  `ssl/test/runner` once with `go test -c`, runs the corpus, and holds
  the result against a floor. Exit 0 passed, 1 failed, 2 could not run —
  the same convention as `zig build interop`, so a machine with no Go
  toolchain and no network gets a SKIP it can read.
- **`bogo/config.json`** — the shim configuration BoGo takes with
  `-shim-config`: an `ErrorMap` from BoringSSL's canonical error strings
  to zssl's error names, and `DisabledTests`, the suppression ledger.

Nothing is vendored. The pin is a commit hash in `bogo/run.zig`; moving
it means re-deriving the floor in the same commit.

## The three numbers

**133 passed.** Cases the runner ran end to end and we satisfied —
including the alert we sent, which BoGo checks by name. 127 of them
drive `ClientHandshake` and 6 drive `ServerHandshake`; see the caveat
below, because that split is the most important fact on this page.

**0 failed** is the gate. A case the runner runs and we cannot satisfy
either gets fixed or gets an entry in `DisabledTests` with a one-line
reason. There are no silent skips.

**7310 declined** — 93% of the corpus. The shim exited 89, PORTING.md's
"unimplemented", and the runner counted the case without running it.
That number is large enough to be the first thing anyone asks about, so
here is what it is made of. Counting each case by the *first* thing the
shim declined:

| Cases | Declined because |
| ---: | --- |
| 2676 | DTLS or QUIC — no datagram record layer, and none planned. |
| 357 | The case hands our server an RSA signing key. See the caveat below. |
| 409 | `-new-x509-credential` — multiple credentials with selection between them. |
| 248 | `-new-rpk-credential` — raw public keys. |
| 208 | A group that is not x25519. |
| 182 | `-accepted-peer-cert-types`. |
| 167 | `-export-keying-material` — RFC 5705 exporters, which zssl has no API for. |
| 324 | `-verify-fail` / `-expect-verify-result` — X.509 validation, the embedder's by design. |
| 281 | `-enable-ocsp-stapling` / `-ocsp-response`. |
| 378 | `-fips-202205`, `-cnsa1-202603`, `-cnsa2-202603`, `-wpa-202304` — compliance policies. |
| 250 | `-signing-prefs` / `-expect-peer-signature-algorithm`. |
| 167 | 0-RTT (`-expect-accept-early-data`, `-expect-reject-early-data`). |
| 123 | Channel ID. |
| 90 | A version cap that is not 1.3. |
| 91 | `-async` — BoringSSL's asynchronous callbacks, which a sans-I/O library has no analogue for. |
| ~1300 | The rest of the flag surface, one flag at a time. |

Roughly 3400 of those — DTLS, QUIC, client certificates, 0-RTT, ECH,
compliance policies, X.509 validation — are scope decisions written down
in DESIGN.md §1 and will never come back. The rest is headroom: the
largest single win available is an RFC 5705 exporter (167 cases), then
exposing the peer's negotiated signature algorithm (128), then honouring
`-signing-prefs` (122).

Each decline names its flag on stderr, so a case that later turns into a
failure says which flag it stumbled on rather than leaving it to
bisection.

### The caveat that matters: the server half is barely covered

Of the 133 passing cases, **127 drive `ClientHandshake` and 6 drive
`ServerHandshake`**:

```
CheckECDSACurve-TLS12                     ECDSACurveMismatch-Sign-TLS13
Server-SignDefault-ECDSA_P256_SHA256-TLS13   Server-SignDefault-ECDSA_P384_SHA384-TLS13
Server-SignDefault-ECDSA_SHA1-TLS13       ServerCipherFilter-ECDSA
```

The cause is structural, not an oversight in the shim: BoGo gives every
server case an RSA leaf unless the case explicitly says otherwise, and
zssl signs ECDSA only — an embedder policy about signing latency
(DESIGN.md §1), not a gap. 357 server cases die on `Credentials.load`
before a byte reaches the state machine, and the runner has no flag that
says "use ECDSA by default".

So read the gate for what it is: **zssl's client half is now
adversarially tested; its server half is not.** That is the opposite of
where zoxy's risk lies, and it is the next thing to fix. The options are
a shim that substitutes its own ECDSA leaf when handed an RSA one — which
buys coverage at the cost of running a configuration the case did not
describe, and would have to be reported separately rather than folded
into this count — or a local patch to the runner's default credential.
Neither is done, and until one is, the server-side numbers here are six.

**The floor is the anti-rot mechanism.** `bogo/run.zig` fails the build
if fewer than `passing_floor` cases pass. `config.json` can disable a
case, but it cannot disable one quietly: the floor falls with it and the
gate goes red. Raise the floor whenever a fix moves the number up.

## The suppression ledger

451 entries in `DisabledTests`, each carrying its reason. By count:

| Entries | Why |
| ---: | --- |
| 341 | TLS 1.0/1.1/1.2 — 1.3-only by design (DESIGN.md §1). The version is declined, and BoGo scores that decline as a failure of a 1.2 case. |
| 35 | Client certificates — out of scope permanently. |
| **35** | **Open gaps BoGo found.** See below. |
| 20 | HelloRetryRequest — the client holds one group, so both shapes are refused structurally (slice 4). |
| 14 | Outcomes that differ by design: a 1.3-only client refuses a version before §4.1.3's downgrade sentinel can matter; a resumed leg offers 1.3 alone against a 1.2-only runner; the runner asserts an initial record version of 0x0301 where §5.1 permits the 0x0303 we send. |
| 6 | Single absent features — X.509 key usage, renegotiation, 0-RTT, Ed25519, post-quantum key exchange — named individually rather than swept up by pattern. |

Everything else zssl lacks — DTLS, QUIC, ECH, PAKE, delegated
credentials, raw public keys, ALPS, Channel ID, NPN, compressed
certificates, RSA signing — never reaches this ledger at all: the shim
exits 89 on the flag that asks for it, and the case is counted among the
7310 rather than suppressed.

## What BoGo found on its first run

Three bugs, fixed in this slice:

1. **`ClientHandshake` never sent `psk_key_exchange_modes`** unless it
   was already resuming. §4.6.1 lets a server issue a NewSessionTicket
   only to a client that has advertised a mode it can resume under, so no
   conforming server would ever give our client a ticket — client-side
   resumption worked against zssl's own server and nothing else. The
   in-tree resumption tests could not see it: both ends were ours.
2. **A mid-handshake alert went out ahead of D.4's dummy
   ChangeCipherSpec.** A peer in compatibility mode is waiting for that
   record before the client's first *protected* one, which is the
   Finished flight on a handshake that completes and the alert on one
   that does not; without it the peer reads the alert as the CCS.
   `sendAlert` now leads with it.
3. **A reachable assertion**: `buildFlightPlaintext` asserted a full
   flight was at least 500 bytes, which a legitimately small ECDSA leaf
   falsifies. The floor is now the encoded chain's own size.

Eight more are open. Each is an entry in the ledger citing this list, 35
suppressed cases between them:

1. **Only one post-handshake message per record.**
   `handlePostHandshake` refuses a non-empty assembler, so two
   NewSessionTickets in one record — or a ticket packed with a KeyUpdate,
   which both Go and OpenSSL emit — is `UnexpectedMessage`. Legal, common,
   and refused. This one needs the event surface to grow a way to drain
   more than one event per record.
2. **The client accepts extensions it never offered.** §4.2 wants
   `unsupported_extension` for an unsolicited server_name ack, a
   `key_share` in EncryptedExtensions, extended_master_secret,
   ec_point_formats, an OCSP or SCT response on Certificate, trust
   anchors, and unknown or duplicate extensions. We ignore all of them.
3. **No §5.4 cap on the decrypted inner plaintext.** DESIGN.md §5 claims
   the cap; the padded cases show content past 2^14 getting through once
   padding is stripped.
4. **No bound on empty application records or on KeyUpdates** within a
   session. BoringSSL caps both; our KeyUpdate ceiling is far above the
   count that should end a connection.
5. **Every non-close_notify alert is fatal**, including the
   warning-level `user_canceled` that §6.1 leaves legal and that JDK 11
   sends in the wild.
6. **A close_notify retires the machine**, so an embedder cannot answer
   it with one of its own — zssl models a close as ending the session
   rather than as §6.1's half-close.
7. **NewSessionTicket extension bodies are not checked** for a minimal
   encoding.
8. **A handful of alert choices differ from BoringSSL's** — trailing data
   after a Certificate answers `bad_certificate` where `decode_error` is
   the better reading, among others.

None of these are exploitable as far as the runner can show; they are
laxity, and laxity is what BoGo exists to find.

## Running it

```sh
zig build bogo                                # the gate
zig build bogo -- -test 'TLS13-*'             # one family
zig build bogo -- -test 'Resume-Client-TLS13-TLS13-TLS' -debug   # one case, hexdumped
zig build bogo -- -include-disabled           # ignore the ledger
```

Anything after `--` goes to the runner verbatim. The first run clones
BoringSSL and downloads Go modules; later runs reuse both. The full log
lands in `zig-out/bogo/bogo.log` and the machine-readable counts in
`zig-out/bogo/results.json`.

## Moving the pin

BoringSSL's `main` moves weekly and BoGo grows cases with it. To bump:
change `boringssl_commit` in `bogo/run.zig`, run the gate, and expect it
to go red — new cases arrive failing. Triage each one into a fix or a
ledger entry, then re-derive `passing_floor` from the new number in the
same commit. A pin bump that does not touch the floor has either learned
nothing or hidden something.

## What else exists

The interop gate (`zig build interop`) runs both directions against the
real `openssl` binary — genuine libssl, no shared code, real sockets —
and the unit suite carries an in-process `std.crypto.tls.Client` leg.
Neither is adversarial; that is the gap this file closes.

The ztls differential stays out, deliberately. A differential against
ztls proves we agree with one other implementation that shares our
*assumptions*; BoGo proves we refuse what the protocol says to refuse,
which is the question a proxy's TLS terminator actually gets asked by the
internet. The differential belongs with zoxy's engine swap anyway — that
is where the two run side by side and disagreement is diagnosable against
a live proxy.
