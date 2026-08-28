# BoGo — wired

BoGo is BoringSSL's adversarial TLS test runner: a Go program that plays
a deliberately hostile peer and drives an implementation through some
thousands of cases, most of which are things a correct stack must
*refuse*. It is the highest-value item on zssl's assurance ladder,
because every other oracle in the tree tests what we accept.

It now runs: `zig build bogo`.

```
bogo: 258 passed, 0 failed, 6918 declined by the shim (89), floor 258
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

**258 passed.** Cases the runner ran end to end and we satisfied —
including the alert we sent, which BoGo checks by name. 134 drive
`ClientHandshake` and 124 drive `ServerHandshake`. The server number was
6 until RSA signing landed, 100 until secp256r1/secp384r1 did, 110 until
§9.2's `missing_extension` did, 111 until §5.4's inner-plaintext cap did,
113 until eight suppressions turned out to be describing bugs that were
already fixed, and 121 until finding 8 was taken apart. The client number
was 121 until §4.2's unsupported_extension landed; see below.

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

Twelve more were open and ten remain — 2 and 3 are fixed and 8 is down to
two cases we intend to keep. All three are kept in place below rather
than renumbered, because the ledger cites these by number. 28 suppressed
cases sit across the ten.

Those 44 are what survived being *measured*. Every OPEN GAP entry was
lifted at once and the corpus run in full: 8 of the 52 passed outright,
all of them under finding 8, none of them a regression anywhere else.
The got-versus-want the runner printed for the other 44 is what the
descriptions below now say, rather than what anyone inferred from a case
name.

1. **Only one post-handshake message per record.**
   `handlePostHandshake` refuses a non-empty assembler, so two
   NewSessionTickets in one record — or a ticket packed with a KeyUpdate,
   which both Go and OpenSSL emit — is `UnexpectedMessage`. Legal, common,
   and refused. This one needs the event surface to grow a way to drain
   more than one event per record.
2. **FIXED — the client accepted extensions it never offered.**
   `checkEncryptedExtensions` looked at ALPN and skipped everything
   else, so a server could hand our client any extension it liked and we
   took it. §4.2 makes that `unsupported_extension`, and it is the half
   of the library zoxy uses to originate.

   The fix is an allow-list rather than a deny-list: of everything zssl
   offers, only `server_name`, `supported_groups` and ALPN are legal in
   EncryptedExtensions, so `key_share` — offered in our ClientHello but
   belonging to ServerHello — is as unsolicited there as an extension we
   never sent. On the Certificate message the leaf's extension block must
   be empty, because zssl requests neither status_request nor SCT;
   intermediates stay ignored, which §4.4.2 asks for and BoGo checks
   both ways.

   Two orderings turned out to be load-bearing, and both were found by
   running the cases rather than reading them. A `server_name` ack is
   parsed before its solicitation is checked, because
   `ExtensionTrailingData-ServerName-Client` wants `decode_error` for a
   malformed ack while `UnsolicitedServerNameAck` wants
   `unsupported_extension` for a well-formed one — check solicitation
   first and the former silently becomes the latter. And an ALPN
   selection when we offered no ALPN is the *extension* being
   unsolicited, not a bad choice inside one, so it stops being
   `illegal_parameter`.

   `captureLeaf` also had to stop turning the refusal into
   `BadCertificate`: an unsolicited extension says nothing about the
   certificate, which may be perfectly good.
3. **FIXED — no §5.4 cap on the inner plaintext *before* padding is
   stripped.** `Protector.open` bounded the content it handed back —
   `content_bytes > plaintext_bytes_max` has been a `record_overflow`
   since slice 1 — but never checked the inner plaintext it was *handed*
   against `record.inner_plaintext_bytes_max` (§5.4's 2^14+1), which is
   why that constant sat defined and unused. So
   `LargePlaintext-TLS13-Padded-16384-1` and `-8193-8192`, both 16386
   inner bytes, were accepted where §5.4 says record_overflow. One line
   in `open`, checked on the framed length before any AEAD work, and both
   cases now pass.

   Worth keeping as a lesson about findings rather than deleting. This
   read "content past 2^14 getting through once padding is stripped"
   until it was measured — which is the half that *was* checked. The case
   numbers were right and the diagnosis was not, so for four slices
   nobody could act on it, and DESIGN.md §5 described a cap the code did
   not have. A finding is a measurement or it is a guess with a case
   number attached.
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
8. **Two alert choices we mean to keep**, down from 19. What was here
   was never one finding, and the label cost four slices:

   - `GarbageCertificate-Client-TLS13` was **a remote panic**, not a
     description. `std.crypto.Certificate.parse` computes where one
     element starts from where the last ended and reads there without a
     bounds check, so seven bytes of garbage from a peer aborted the
     process — in ReleaseSafe, which is what release builds ship, and
     `catch` cannot answer a safety panic. `src/der_bounds.zig` walks the
     framing first and refuses anything std could step off the end of.
   - `ALPNServer-EmptyProtocolName` was **accepted outright**. The
     server stopped at the first protocol it liked, so a list whose later
     entries were malformed passed whenever an earlier one matched. ALPN
     framing is now validated where the ClientHello is parsed, which is
     not a question the server's configuration gets to answer.
   - `NoSupportedCurves-TLS13` was **the other half of §9.2**. A hello
     offering no PSK can only be attempting (EC)DHE, so a missing
     `supported_groups` is the same abort as a missing `key_share`.
   - Four were **the wrong error, not the wrong alert**: trailing bytes
     after EncryptedExtensions, a Certificate, or a CertificateVerify are
     a framing fault, and so is a NewSessionTicket with an empty ticket.
     Those answered `bad_certificate`, `decrypt_error` and
     `unexpected_message` — verdicts about the thing being framed rather
     than about the framing. `MalformedMessage` and
     `MalformedCertificate` now carry them, and §6.2's decode_error is
     what goes on the wire.
   - Two were **ordering**: a run of noise is answered as "not a TLS
     record" before "not a content type I know", which is what
     `record.zig`'s own comment already said the major-byte check was
     for; and an unrecognised *inner* content type is now
     `UnknownContentType` rather than the catch-all for a record that
     never yielded a type at all.

   The two that remain are genuine disagreements, and we keep our answer:

   - `SendBogusAlertType` sends an alert whose level byte is 0x42. We
     answer decode_error, BoringSSL illegal_parameter. Neither is
     mandated, and the first draft of this entry overstated it: TLS 1.3
     declares `AlertLevel` an open enum — `{ warning(1), fatal(2), (255) }`
     — and deprecates the field outright, so "out of range" is not the
     clean argument it looked like. What we keep is the refusal: an
     unrecognised level is a field we cannot interpret, and §6.2's
     decode_error is the closest description of that. Ignoring the byte
     entirely, which §6 arguably licenses, would be the other defensible
     answer and is not the one BoGo wants either.
   - `UnencryptedEncryptedExtensions` sends EncryptedExtensions as a
     plaintext handshake record. We answer unexpected_message, BoringSSL
     bad_record_mac because it attempts decryption. §5.2 gives protected
     records content_type application_data, so a handshake-typed record
     there is a message at the wrong moment, and we would rather not run
     peer bytes through the AEAD when the record's own type says it is
     not protected.

   The lesson stands and is now paid for: an alert the peer cannot read,
   a panic, a missing check and a misclassified error all look identical
   from outside — the runner just says the description differs. Nothing
   is filed here without the got-versus-want quoted beside it.
9. **A duplicate extension in the peer's hello is accepted** rather than
   refused, on both sides.
10. **A PSK offer whose binder list does not match its identity list**,
    8 cases, of which only 3 are this finding. `Resume-Server-{Extra
    PSKBinder,ExtraIdentityNoBinder,BinderWrongLength}` draw
    `decode_error` out of `MalformedExtension` where §4.2.11 wants
    `illegal_parameter`, or `decrypt_error` where the binder is merely
    wrong rather than miscounted.

    The other 5 are the `-SecondBinder` variants, and they are not a
    defect at all: that suffix forces a HelloRetryRequest
    (`resumption_tests.go`, "Force a HelloRetryRequest by predicting an
    empty curve list"), so the corrupt binder rides the *second*
    ClientHello, and `selectPsk` ignores PSK offers on a retry hello on
    purpose — the binder there hashes the §4.4.1 surgery transcript,
    which zssl does not carry. They belong to that scope decision and
    should move to it when the HRR+PSK path is either carried or
    written off.

    Recorded because the first reading of this was wrong in the
    instructive way: the runner says `didResume is false, but we expected
    the opposite`, which looks like an offer we neither resumed nor
    refused, and is in fact one we declined by written policy. A symptom
    is not a cause even when the symptom is precise.
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
