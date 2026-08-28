# BoGo — wired

BoGo is BoringSSL's adversarial TLS test runner: a Go program that plays
a deliberately hostile peer and drives an implementation through some
thousands of cases, most of which are things a correct stack must
*refuse*. It is the highest-value item on zssl's assurance ladder,
because every other oracle in the tree tests what we accept.

It now runs: `zig build bogo`.

```
bogo: 232 passed, 0 failed, 6918 declined by the shim (89), floor 232
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

**232 passed.** Cases the runner ran end to end and we satisfied —
including the alert we sent, which BoGo checks by name. 121 drive
`ClientHandshake` and 111 drive `ServerHandshake`. The server number was
6 until RSA signing landed, 100 until secp256r1/secp384r1 did, and 110
until §9.2's `missing_extension` did; see below.

**0 failed** is the gate. A case the runner runs and we cannot satisfy
either gets fixed or gets an entry in `DisabledTests` with a one-line
reason. There are no silent skips.

**6918 declined** — 88% of the corpus. The shim exited 89, PORTING.md's
"unimplemented", and the runner counted the case without running it.
That number is large enough to be the first thing anyone asks about, so
here is what it is made of. Counting each case by the *first* thing the
shim declined:

| Cases | Declined because |
| ---: | --- |
| 2676 | DTLS or QUIC — no datagram record layer, and none planned. |
| 409 | `-new-x509-credential` — multiple credentials with selection between them. |
| 378 | `-fips-202205`, `-cnsa1-202603`, `-cnsa2-202603`, `-wpa-202304` — compliance policies. |
| 324 | `-verify-fail` / `-expect-verify-result` — X.509 validation, the embedder's by design. |
| 281 | `-enable-ocsp-stapling` / `-ocsp-response`. |
| 250 | `-signing-prefs` / `-expect-peer-signature-algorithm`. |
| 248 | `-new-rpk-credential` — raw public keys. |
| 105 | A group we do not hold, or a `-curves` set our client cannot honour — it offers x25519 alone whatever it is told, and the server cannot be told to accept a narrower set. |
| 182 | `-accepted-peer-cert-types`. |
| 167 | `-export-keying-material` — RFC 5705 exporters, which zssl has no API for. |
| ~1800 | The rest of the flag surface, one flag at a time. |

Roughly 3400 of those — DTLS, QUIC, client certificates, 0-RTT, ECH,
compliance policies, X.509 validation — are scope decisions written down
in DESIGN.md §1 and will never come back. The rest is headroom: the
largest single wins available are an RFC 5705 exporter (167 cases),
exposing the peer's negotiated signature algorithm (128), honouring
`-signing-prefs` (122), and letting the two machines be *told* which
groups to use — a server that can be restricted to a subset and a client
that can offer something other than x25519 would let the rest of the
`-curves` corpus run against the key exchange that already completes it.

Each decline names its flag on stderr, so a case that later turns into a
failure says which flag it stumbled on rather than leaving it to
bisection.

### Both halves are covered, and one of them nearly was not

The first wiring of this gate passed 133 cases, of which **6** drove the
server. The cause was structural rather than an oversight in the shim:
BoGo gives every server case an RSA leaf unless the case says otherwise,
and zssl signed ECDSA only, so 357 server cases died inside
`Credentials.load` before a byte reached the state machine. The gate
adversarially tested the client half and almost nothing else — the
opposite of where a terminating proxy's risk sits.

RSA-PSS signing (DESIGN.md §1) closed that, and the server count went
from 6 to 100; secp256r1 and secp384r1 key exchange took it to 110, and
every TLS 1.3 case BoGo has for those curves — the valid shares, the
compressed ones, the points off the curve, the truncated and padded ones
— now passes. The residue those two curves left behind is 37 cases, and
all 37 are pre-1.3. It is worth being precise about what the fix bought:
every server-side finding below — both version-tolerance bugs, the PSK
binder counting, the ClientHello parse strictness — was invisible until
the server half could run at all. A gate that covers one half of a
library reads exactly like a gate that covers both.

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

Twelve more are open. Each is an entry in the ledger citing this list, 54
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
3. **No §5.4 cap on the inner plaintext *before* padding is stripped.**
   `Protector.open` bounds the content it hands back — `content_bytes >
   plaintext_bytes_max` has been a `record_overflow` since slice 1 — but
   never checks the inner plaintext it was handed against
   `record.inner_plaintext_bytes_max` (§5.4's 2^14+1), which is why that
   constant is defined and unused. So `LargePlaintext-TLS13-Padded-16384-1`
   and `-8193-8192`, both 16386 inner bytes, are accepted where §5.4 says
   record_overflow.

   Worth reading as a lesson about findings: this said "content past 2^14
   getting through once padding is stripped" until 2025-08-28, which is
   the half that *was* checked. The case numbers were right and the
   diagnosis was not, so nobody could act on it. A finding is a
   measurement or it is a guess with a case number attached.
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
   the better reading, among others. The largest single group at 19
   cases, and the least interesting: we refuse, for the right reason,
   with the wrong description. `MissingKeyShare-Server-TLS13` left this
   group when tlsfuzzer's `keyshare-omitted` showed the cause was not a
   description at all: §9.2's `missing_extension` was never being sent,
   because an omitted `key_share` was read as an empty one. See
   docs/TLSFUZZER.md, finding 6.
9. **A duplicate extension in the peer's hello is accepted** rather than
   refused, on both sides.
10. **A PSK offer whose binder list does not match its identity list** is
    refused late, as a malformed extension, rather than at the count
    §4.2.11 specifies.
11. **A resumed session is accepted under a suite the ClientHello did not
    offer.**
12. **`psk_key_exchange_modes` is not consulted before issuing a
    NewSessionTicket**, which §4.6.1 requires — the mirror, on the server
    side, of the client bug in the fixed list above.

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
