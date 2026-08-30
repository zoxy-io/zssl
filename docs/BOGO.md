# BoGo — wired

BoGo is BoringSSL's adversarial TLS test runner: a Go program that plays
a deliberately hostile peer and drives an implementation through some
thousands of cases, most of which are things a correct stack must
*refuse*. It is the highest-value item on zssl's assurance ladder,
because every other oracle in the tree tests what we accept.

It now runs: `zig build bogo`.

```
bogo: 348 passed, 0 failed, 6835 declined by the shim (89), floor 348
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
  embedder's by design (DESIGN.md §1).
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

**348 passed.** Cases the runner ran end to end and we satisfied —
including the alert we sent, which BoGo checks by name. It was 324 until
the client could report and restrict its signature algorithms
(finding 19), and 278 until
the client could answer a HelloRetryRequest: a single-group client that
refused every retry structurally kept 26 patterns declined, and
un-declining them is where the 21 came from. The last seven are the
§4.4.1 retry binder (finding 13 below) — two that carry a PSK across a
retry, one per machine, and five malformed offers on a second hello
that could not be refused while the whole message was being ignored.

The per-machine split this paragraph used to give — 146 client, 132
server — is not restated here, because the gate does not compute one and
the log's names do not carry it reliably. A number nobody can re-derive
is a number that rots; `grep -c '^PASSED' zig-out/bogo/bogo.log` is the
one that can.

The server half's history is worth keeping even so, because each step
names a defect: it was
6 until RSA signing landed, 100 until secp256r1/secp384r1 did, 110 until
§9.2's `missing_extension` did, 111 until §5.4's inner-plaintext cap did,
113 until eight suppressions turned out to be describing bugs that were
already fixed, 121 until finding 8 was taken apart, 124 until §4.2.9's
psk_key_exchange_modes was enforced, 127 until §4.2's duplicate rule
did, 128 until §4.2.11's binder rules were told apart, and 131 until one
record could yield more than one event. The client
number was 121 until §4.2's unsupported_extension landed, 134 until
finding 4's flood ceilings did, 136 until finding 5 stopped refusing
`user_canceled`, 139 until that same duplicate rule, 140 until finding 6
split the close in two, 141 until finding 7 read the ticket's
extension block, and 143 until §4.6.3's update requests were coalesced, and
144 until one record could yield more than one event; see below.

**0 failed** is the gate. A case the runner runs and we cannot satisfy
either gets fixed or gets an entry in `DisabledTests` with a one-line
reason. There are no silent skips.

**6835 declined** — 86% of the corpus. The shim exited 89, PORTING.md's
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
| 105 | A group we do not hold, or a `-curves` set we cannot honour — now only a set naming a group neither machine completes, or one without x25519, which is the group our client always shares. |
| 182 | `-accepted-peer-cert-types`. |
| 167 | `-export-keying-material` — RFC 5705 exporters, which zssl has no API for. |
| ~1800 | The rest of the flag surface, one flag at a time. |

Roughly 3400 of those — DTLS, QUIC, client certificates, ECH,
compliance policies, X.509 validation — are scope decisions written down
in DESIGN.md §1 and will never come back. The rest is headroom: the
largest rows left are an RFC 5705 exporter (167 cases), exposing the
peer's negotiated signature algorithm (128), and honouring
`-signing-prefs` (122) — *rows*, deliberately, not wins. All three have
now been sampled, and they came out very differently:

| Row | Cases | Would run | What is in the way |
| --- | ---: | ---: | --- |
| `-export-keying-material` | 167 | **6** | the rest are DTLS, QUIC or pre-1.3 |
| `-expect-peer-signature-algorithm` | 128 | **~32** | half are pre-1.3; half of the rest verify a *client* certificate |
| `-signing-prefs` | 122 | **~31** | `Client-Sign-*` is client certificates |

The exporter row is small because `cipher_suite_tests.go` sets the flag
on every `-server`/`-client` case but generates none at TLS 1.3, and the
dedicated `export_tests.go` family is mostly DTLS and QUIC.

The two signature-algorithm rows are the real headroom, and cheaper than
they look because each has a precedent in the tree. The client never
records the peer's scheme — it is a local in `verifyCertificate`,
checked and dropped — while the server already keeps `signature_scheme`
and `interop` asserts on it; that is one field. Restricting which
schemes the server will sign with is `Config.groups` one type over.
Between them the shim needs three flags it does not have:
`-expect-peer-signature-algorithm`, `-verify-prefs`, `-signing-prefs`.

Read those two figures as cases that would *run*, not cases that would
pass. Roughly two thirds of them are algorithms we do not hold, so they
expect a refusal, and BoGo grades refusals by alert name — finding 8 is
what that costs when we disagree.

**Read this table as "first thing declined", not "cases a fix would
buy".** `-curves` is the worked example, and it cost a slice to learn.
This paragraph used to name it as one of the largest wins, on the
strength of its 105-case row; both machines now take a configured group
list, and honouring it un-declined **11** cases, every one of them a
TLS 1.0/1.1/1.2 conversation we have to decline anyway. The other 94 hit
a second unimplemented flag immediately behind the first. A row's number
is an upper bound that is usually loose, because a case declined for one
reason is very often declined for three.

The 11 are worth keeping in mind for a different reason: `-curves` was
the *only* thing declining them. The runner sets its `MaxVersion` on its
own `Config` rather than passing the shim a `-max-version` flag, so
nothing on the wire tells the shim those cases are pre-1.3 — they were
being excluded by accident, and their RSA twins had been on the ledger
by name all along.

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

Twelve more were open, and every one that was a defect is now fixed: 1,
2, 3, 4, 5, 6, 7, 9, 10 and 12. Three findings still carry ledger
entries, 8 suppressed cases between them — 5 under finding 10, 2 under
8, 1 under 11 — and **none of them is an OPEN GAP**. Finding 8 is two
divergences we intend to keep, 11 is a documented non-defect, and
finding 10's remaining 5 are a scope decision filed under its number,
which is why findings marked fixed still have entries against them.
`grep 'OPEN GAP' bogo/config.json` returns nothing, which is the whole
point of reserving that phrase for defects.
All twelve keep their numbers rather than being renumbered, because the
ledger cites them by number.

Those 44 are what survived being *measured*. Every OPEN GAP entry was
lifted at once and the corpus run in full: 8 of the 52 passed outright,
all of them under finding 8, none of them a regression anywhere else.
The got-versus-want the runner printed for the other 44 is what the
descriptions below now say, rather than what anyone inferred from a case
name.

1. **FIXED — only one post-handshake message per record**, and — a
   second defect this entry was hiding — one KeyUpdate answered per
   request rather than per run of them. Four cases, of which three were
   the first and one was never it.

   **FIXED.** `handlePostHandshake` refused a non-empty assembler, so
   two NewSessionTickets in one record — or a ticket packed with a
   KeyUpdate, which both Go and OpenSSL emit — was `UnexpectedMessage`.
   Legal, common, and refused.

   The event surface grew a way to say "there is more": `drain` returns
   the next event from a record `handleRecord` already took, and null
   once none remain. At the time both roles could also answer `.none`,
   an event meaning "this advanced nothing", and the two were kept
   apart deliberately — see the mistake below. `.none` is gone now:
   `handleRecord` returns `?Event` too, `nextPostHandshake` skips the
   messages that resolve to nothing, and null still comes only from the
   assembler, so the distinction the mistake needed is preserved without
   a member for it. The loop is `while (event) |ready| : (event = try
   drain(&out))`.

   Two things fell out of building it, and both are the same mistake in
   different clothes — inferring "no more messages" from something other
   than the assembler.

   The first was mine and the review caught it. `drain` on the client
   collapsed `.none` into null, and `.none` is what a KeyUpdate carrying
   update_not_requested produces after being *consumed*. A peer packing
   `[ticket, KeyUpdate, ticket]` therefore got its second ticket
   stranded, and the next `handleRecord` blamed the embedder for it with
   `EventsPending` — a guard meant for embedder error, reachable from
   the wire. Null now comes only from `assembler.next()` having nothing,
   and both roles share one dispatch so neither can drift. That is still
   the rule after `.none` was removed: the silent message is skipped,
   never returned as the end of the run. `client_server_test` walks that
   exact packing and counts both tickets.

   The second is why that guard exists at all. `Assembler.push` appends
   *after* pending bytes, so an embedder that never drains does not lose
   the extra message: it takes it one record late, against receive keys
   the peer has already rotated past, and the symptom is
   `AuthenticationFailed` on a record that is perfectly good.
   `hasComplete` tells a waiting message from an arriving one — `empty`
   cannot — so `handleRecord` can say `EventsPending` instead.

   `Shutdown-Shim-KeyUpdate-TLS-Sync-PackHandshake` joined this finding
   when finding 6 made the shim read after its own close_notify instead
   of returning: it had been passing because nothing looked at it. Its
   `-TLS-Sync` and `-SplitHandshakeRecords` siblings kept passing
   throughout, which is what isolated the cause to packing rather than
   to the shutdown path.

   **FIXED — `KeyUpdate-Requested` was not this gap at all**, and only
   running it said so: our stderr was empty, because we never errored,
   and the *runner* refused a KeyUpdate we had sent. §4.6.3 ties the
   obligation to the next application record — "the receiver MUST send a
   KeyUpdate of its own ... prior to sending its next Application Data
   record" — rather than to each request, so one answer discharges a
   whole run of requests arriving with no application data between them.
   We answered all five, and the runner says in as many words that "the
   shim should respond only once". `session_keys.zig` tracks whether our
   answer still precedes what we send next; `sealApplicationData` is now
   the one way to send application data, so the flag cannot be left
   behind by a caller who forgot it. The early return happens before any
   rotation, because rotating our transmit side without telling the peer
   would desynchronise the keys the message exists to agree on.
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
   from the start — but never checked the inner plaintext it was *handed*
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
4. **FIXED — no bound on empty application records or on KeyUpdates**
   within a session. Both are the same attack: a record that is legal,
   costs a decryption, and returns nothing an embedder can act on. §5.1
   permits an empty application_data record and §4.6.3 puts no limit on
   how many KeyUpdates a peer may send, so nothing in RFC 8446 caps
   either and the limit is policy. `src/flood.zig` now holds both, at
   BoringSSL's numbers because BoGo is what measures them: 32
   consecutive of either, the 33rd ends the connection with
   unexpected_message.

   *Consecutive* is the whole of it, and the two counters reset on
   different things. Any record carrying content clears the empty-record
   count, because a byte arrived at all. Only *application* bytes clear
   the KeyUpdate count, because a KeyUpdate answered by a KeyUpdate is
   still no progress — which is also why an empty application record
   does not clear it. A peer interleaving real traffic never approaches
   either ceiling, and a long-lived connection may legitimately send far
   more than 32 KeyUpdates in total.

   The pre-existing `rotations_max` (1 << 16) was not this limit and is
   not a substitute for it: it is our own generation budget, reachable
   only by rotating legitimately tens of thousands of times. It was
   called `TooManyKeyUpdates`, which is what made the two look like one
   thing, and is now `RotationsExhausted` — named for the budget, beside
   `SequenceExhausted`, and still an internal_error rather than a
   verdict about the peer. `TooManyKeyUpdates` now means what BoringSSL's
   `:TOO_MANY_KEY_UPDATES:` means.

   One case moved that was not the finding. `TooManyChangeCipherSpec-`
   `{Server,Client}-TLS13` expects `:TOO_MANY_EMPTY_FRAGMENTS:`, because
   BoringSSL counts the handshake's dummy ChangeCipherSpec records into
   the same counter. zssl does not reach that counter: `ccs_seen_max` is
   2, so the stricter §5 window rule fires first and answers
   `UnexpectedMessage`. Same alert on the wire, different error name, so
   the ErrorMap carries both — which is what that table is for, and the
   reason those two cases are not silently re-suppressed.
5. **FIXED — every non-close_notify alert was fatal**, including the
   warning-level `user_canceled` that §6.1 leaves legal and that JDK 11
   sends in the wild. TLS 1.3 meant to remove warning alerts and left
   `user_canceled` defined without saying how to handle it; ignoring it
   is what BoringSSL, NSS and OpenSSL all do, so refusing it broke real
   peers rather than hostile ones. `alert.disposition` now sorts an
   alert four ways — close, ignore, refuse, fatal — in one place,
   because both handshakes were deciding it with the same nine lines.

   Ignoring is not free, so it is bounded like the other two ceilings:
   `warning_alerts_max` is 4, BoringSSL's `kMaxWarningAlerts`, which is
   where `SendUserCanceledAlerts-TLS13` (4 alerts, must pass) and
   `-TooMany-TLS13` (5, must fail) sit either side of the line. Any
   *other* warning-level alert is `BadAlert` and §6.2's decode_error,
   which is `SendWarningAlerts-TLS13`. It is a new error rather than
   `MalformedAlert` because the alert is well-formed: we understand it
   and decline it, which is a different sentence.

   Finding 4's guard had a bug this exposed, fixed here. `observeRecord`
   treated any record carrying content as progress, and an alert carries
   two bytes — so a peer alternating four warning alerts with a fifth
   would have refilled its own budget forever and the ceiling would have
   bounded nothing. BoringSSL avoids this by returning from
   `ssl_process_alert` before its reset runs, which reads like an
   accident of control flow and is load-bearing. An alert is never
   progress; a test pins it for all three counters.
6. **FIXED — a close_notify retired the machine**, so an embedder could
   not answer it with one of its own. §6.1 closes one direction at a
   time and zssl modelled a close as ending the session, which is one
   state where the protocol has two.

   Both halves were broken by the same missing distinction. After the
   *peer's* close_notify an embedder could not reply with its own —
   `sendClose` asserted `.connected`, so answering was an abort rather
   than an error. After *our* close_notify we stopped reading, so a
   stream that simply stopped could not be told from one that closed
   cleanly, which is the difference between a shutdown and a truncation
   attack.

   `.closed` is now three states: `close_sent`, `close_received`, and
   `closed` for both. Every entry point asks `writable()` or
   `readable()` instead of comparing against `.connected`, which is
   where the old model kept leaking — the §5 ChangeCipherSpec window,
   the protected-record guard, and the application_data branch each had
   their own `== .connected` and each meant something slightly
   different by it. One of those was still wrong after the first pass,
   and the scenario test caught it: a peer is entitled to keep sending
   application data until it closes its own direction.

   One thing §6.1 forbids that the new states make reachable: a
   KeyUpdate asking for one back, arriving after our close_notify.
   Nothing goes out after that alert, so the response is dropped while
   the receive side still rotates — which is what lets us read on to
   the peer's close.

   `bogo/shim.zig` grew the other half. It used to send close_notify
   and return, so `-check-close-notify` was never consulted and those
   cases passed vacuously; it now reads on until the peer closes.
   Getting that right needed both shapes of "the peer went away": a
   clean end of stream, and a reset, which is what a peer that closes
   without draining actually produces.

   Two ErrorMap entries carry the verdicts, because BoGo names them in
   BoringSSL's vocabulary. `Unexpected SSL_shutdown result: -1 != 1` is
   our `NoCloseNotify`, and `:SSLV3_ALERT_DECOMPRESSION_FAILURE:` is our
   `PeerAlert` — which is worth noticing as a limit rather than a
   translation: zssl reported *that* the peer sent a fatal alert and
   never *which*, so an embedder needing the description did not have
   it. Finding 17 closed that, and the mapping named here is exact now.
7. **FIXED — NewSessionTicket extension bodies were not checked** for a
   minimal encoding. §4.6.1's `extensions` block was read as a length
   and skipped, which is not the same as ignoring it: zssl acts on none
   of these extensions, but an extension whose body does not parse is a
   malformed message whether or not its meaning would have changed
   anything. The block is walked now, and each extension with a grammar
   we know is held to it. An unknown one stays opaque — there is nothing
   to check it against, and BoGo's `UnknownTicketFlags` cases say so.

   `tls_flags` (draft-ietf-tls-tlsflags, extension 62) is the one with a
   grammar: `flags<1..255>`, one bit per flag, minimally encoded. The
   two refusals answer differently, which is the part worth measuring
   rather than assuming. An empty or over-long list is framing that does
   not parse — §6.2's decode_error, `TLS13-Client-EmptyTicketFlags`. A
   list that parses and then ends in a zero byte is well framed and says
   something the grammar forbids, so it is an illegal parameter rather
   than a decode failure: `TLS13-Client-NonminimalTicketFlags`, and the
   new `NonMinimalEncoding` carries it.

   §4.2's duplicate rule applies to this block like any other, so
   finding 9's pre-pass runs here too — a fourth extension block, and
   the reason that check went into `wire` rather than into a parser.
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

   The two that remain are genuine disagreements, and we keep our
   answer. Their ledger entries read "KEEP" rather than "OPEN GAP",
   because nothing here is unfixed: both cases refuse the input exactly
   as BoGo wants, and only the alert description differs. Reserving
   "OPEN GAP" for defects is what lets `grep 'OPEN GAP'` be the count of
   what is actually open.

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
9. **FIXED — a duplicate extension in the peer's hello was accepted**
   rather than refused, on both sides. §4.2 is one sentence: "There MUST
   NOT be more than one extension of the same type in a given extension
   block." The one-line description hid two different bugs, and only
   running the cases separated them.

   Server side, we accepted the hello outright. The parser policed
   duplicates through a `trackedBit` bitset covering the eight
   extensions it understood, and a comment reasoned that "a duplicate we
   would ignore anyway is not this parser's fight" — which sounds right
   and is not what §4.2 says. BoGo duplicates type `0xffff` precisely
   because nobody recognises it. The rule is about the block being well
   formed, not about what its contents mean, so every type is tracked
   now and the bitset is gone.

   Client side, we answered unsupported_extension where §6.2 wants
   decode_error. The check was folded into the parse loop, and the loop
   refuses the first extension it does not recognise — so it returned on
   the first `0xffff` and never reached the second. BoGo places the pair
   first and last in the block for exactly this reason. The rule is now
   a pre-pass over the whole block before any of it is acted on, which
   is also how BoringSSL does it (`checkDuplicateExtensions`), and it
   covers all three blocks zssl reads: ClientHello, ServerHello and
   EncryptedExtensions.

   The ordering lesson is finding 2's, again: a verdict about framing
   has to be reached before a verdict about content, or the second
   silently answers for the first.
10. **FIXED — a PSK offer whose binder list does not match its identity
    list**, 3 of the 8 cases; the other 5 were never this finding and
    now say so.

    All three drew `decode_error` out of one `MalformedExtension`. The
    fix is that §4.2.11 describes three different faults, which now
    answer differently:

    - the two lists both parse and disagree on their length —
      `Resume-Server-ExtraPSKBinder` has a binder too many,
      `-ExtraIdentityNoBinder` an identity too many. Nothing is
      malformed; the hello contradicts itself, which is
      illegal_parameter and the new `BinderCountMismatch`;
    - a binder whose length is not an HMAC output's
      (`-BinderWrongLength`). It cannot be the right MAC for any
      transcript, so it does not *validate* rather than does not
      *parse*: §4.2.11.2's decrypt_error, and the new `BadBinder`;
    - no binder list at all (`-NoPSKBinder`). §4.2.11 writes
      `binders<33..2^16-1>`, so an empty section is framing that does
      not parse, and `MalformedExtension` still answers it.

    That third one is why this took three passes. The first fix checked
    the full 33-byte floor on the section, which is what the grammar
    says — and swallowed `-BinderWrongLength`, because a short binder
    makes the section short too. The floor here has to be emptiness
    alone, with each entry's own length left to the loop that reads it.
    A grammar transcribed correctly can still be checked in the wrong
    place, and `-NoPSKBinder` was passing before this slice, so getting
    it wrong was a regression rather than a miss.

    The other 5 are the `-SecondBinder` variants, and at the time they
    were not a defect: that suffix forces a HelloRetryRequest
    (`resumption_tests.go`, "Force a HelloRetryRequest by predicting an
    empty curve list"), so the corrupt binder rides the *second*
    ClientHello, and `selectPsk` ignored PSK offers on a retry hello on
    purpose — the binder there hashes the §4.4.1 surgery transcript,
    which zssl did not carry. Their entries said "they move again if the
    HRR+PSK path is ever carried", and finding 13 carried it: all five
    now reach the checks above and pass, and their ledger entries are
    gone rather than restated. Three faults told apart is worth nothing
    on a message that is never read.

    Recorded because the first reading of this was wrong in the
    instructive way: the runner says `didResume is false, but we expected
    the opposite`, which looks like an offer we neither resumed nor
    refused, and is in fact one we declined by written policy. A symptom
    is not a cause even when the symptom is precise.
11. **NOT A DEFECT — a resumed session accepted under a suite the
    ClientHello did not offer.** Read the runner's own comment before
    acting on this one, which is what took two attempts:

        In TLS 1.3, clients may advertise a cipher list which does not
        include the selected cipher. Test that we tolerate this. Servers
        may resume at another cipher if the PRF matches and are not doing
        0-RTT, but BoringSSL will always decline.

    `Resume-Server-UnofferedCipher-TLS13` offers AES-128-GCM-SHA256 for a
    ChaCha20-SHA256 ticket. The PRF matches, so resuming is permitted and
    `expectResumeRejected` encodes BoringSSL's policy rather than a
    requirement. Its sibling `TLS13-NoTicket-NoAccept` was ours but not
    the library's: `SSL_OP_NO_TICKET` means the server must not *accept*
    a ticket either, and the shim was using the flag only to skip minting
    one. Fixed there.
12. **FIXED — `psk_key_exchange_modes` was not consulted**, in both
    directions.

    Outbound, §4.2.9: servers "SHOULD NOT send NewSessionTicket with
    tickets that are not compatible with the advertised modes", and zssl
    minted one for anybody. `sendNewSessionTicket` now refuses with
    `TicketNotPermitted` — before the `errdefer` that fails the machine,
    because ticketing a client that must ignore the ticket is the
    embedder's policy mistake and not a broken connection.
    `ticketPermitted` is the question to ask instead, and both harnesses
    now ask it.

    The rule is deliberately narrow: false only when the hello advertised
    modes and left ours out of them. A hello advertising *none* has
    nothing for a ticket to be incompatible with, and the first version
    of this fix refused those too — which broke ten of tlsfuzzer's
    `connection-abort` conversations, all waiting on a ticket their hello
    never asked about. They are legitimate clients, and the RFC's wording
    is about compatibility rather than about permission.

    Inbound, §4.2.9 and §9.2: "In order to use PSKs, clients MUST also
    send a psk_key_exchange_modes extension". An offer arriving without
    one was answered with a full handshake — a malformed offer hidden
    behind a working connection — and is now missing_extension.

13. **FIXED — a PSK could not cross a HelloRetryRequest**, in either
    direction, and the second ClientHello's own rule was missing with
    it. Seven cases: two declined together because they are one scope
    cut seen from two ends, and five that finding 10 had parked against
    this one being fixed.

    §4.2.11.2 computes the binder over
    `Transcript-Hash(Truncate(ClientHello))`, and on a *second* hello
    that transcript is not the hello: §4.4.1 has replaced CH1 with a
    synthetic `message_hash` message and put the HelloRetryRequest
    behind it, so the hash covers three things and the truncation is
    only the last. Both halves hashed the truncation alone, so neither
    could carry a PSK across a retry — the client dropped its offer
    (`CurveID-Resume-Client-TLS13`) and the server ignored one
    (`Resume-Server-OmitAllPSKsOnSecondClientHello`).

    The surgery already existed on both machines, for the handshake
    transcript. What was missing was a way to read that transcript with
    a *non-message* on the end, which is what the truncated hello is —
    its length header still counts the bytes that were cut, so
    `Transcript.update` rejects it, and rightly. `Transcript.hashWith`
    is that read: the prefix is asked for rather than rebuilt, so the
    two sides cannot disagree about what CH1 hashed to.

    Fixing the server exposed the rule underneath.
    `Resume-Server-OmitAllPSKsOnSecondClientHello` is not about binders
    at all — the client simply *omits* the extension on CH2 — and it
    wants `missing_extension`. §4.1.2 is why: after a retry the client
    "MUST send the same ClientHello without modification, except as
    follows", and that list permits updating a `pre_shared_key`, never
    dropping it. The server now remembers whether CH1 carried one,
    because CH1's bytes are gone by the time CH2 arrives.

    Two orderings turned out to be load-bearing, both for the same
    reason — the binder is checked against a transcript keyed to a
    suite. On the server, §4.1.4's "the retry keeps the suite" check
    moved *ahead* of the PSK, or a CH2 that changed the suite would have
    its binder verified under one hash against a ladder built for
    another. On the client, the binder is patched before the transcript
    absorbs CH2, because the binder is part of the message it absorbs.

    The client also learned when *not* to carry the offer: §4.2.11's
    "SHOULD NOT offer any pre-shared keys associated with a hash other
    than that of the selected cipher suite". A ticket's PSK is a hash
    long by §4.6.1's derivation, so its length is its hash, and a retry
    naming a suite that hashes to another length leaves it behind.
    `psk_offered` — what the hello on the wire actually carries — is now
    what gates accepting a `selected_identity`, rather than what the
    config holds; those were the same question until a retry could
    change the hello, and telling them apart is what keeps a server from
    naming an identity we never sent.

    The five extra cases are finding 10's `-SecondBinder` variants, and
    they came for free in the way that says the scope cut was hiding
    something: a malformed binder on CH2 — one too many, one too few,
    the wrong length, none at all — used to be *ignored* along with the
    message carrying it, so three carefully distinguished faults met a
    hello nobody read. They now reach the same checks their first-hello
    twins do.

14. **FIXED — early data we declined was mistaken for ciphertext.** Four
    cases, and a blanket ledger reason that was covering three more it
    had no business covering.

    §4.2.10 lets a client send 0-RTT data immediately behind its
    ClientHello. zssl never accepts it — DESIGN.md §1 puts acceptance
    out permanently, on §8 grounds — but *declining* is not a decision
    we get to make in time:
    the client learns of it only when our flight arrives, so the records
    are already on the wire. "The server ... MUST skip past" them, and
    we were opening them instead, answering a decryption failure for a
    fault the peer did not commit.

    Skipping by content type is the obvious fix and it is wrong, which
    cost a round of debugging: an encrypted handshake record is
    `application_data` on the wire too, so a server that discards by
    type discards the client's Finished and wedges. §4.2.10 says how
    instead — "trial decryption ... to find the first non-0-RTT message"
    — and that is two rules, not one:

    - before our flight there is no receive key at all, so every
      protected record in that window is early data and nothing else
      could be. That is the HelloRetryRequest gap, where the client is
      sending data at a server that has not keyed yet;
    - after it, a record that will not open is early data and a record
      that opens ends the search. The window shuts on the first success,
      which is what makes `SkipEarlyData-Interleaved-TLS13` — early data
      wedged into the gap between two fragments of the Finished — a
      decryption failure rather than a discard.

    The ceiling is BoringSSL's `kMaxEarlyDataSkipped` and so is the
    reason for having one; what it counts is not. They add the bytes
    consumed from the stream, header included, and we add the record's
    payload, which is what §4.2.10 measures early data in. Both refuse
    BoGo's 2^14+1; only ours admits the client that sends exactly 2^14,
    and tlsfuzzer's `test-tls13-0rtt-garbage` is written around that
    client. Five bytes a record decided a whole script.

    That script is now the 22nd, at eight of its nine conversations —
    the ninth wants a downgrade to TLS 1.2 and is excluded by name.

    Counting payload alone left a hole the review found, and it is worth
    recording because the fix is the whole reason the ceiling exists.
    §5.1 lets an application_data record carry nothing, so a peer paying
    only for headers spent none of the budget and could hold the window
    open indefinitely at five bytes a turn — the exact attack the
    ceiling is quoted as preventing, reintroduced by the accounting
    chosen to satisfy a test. Every skipped record now costs a byte at
    minimum, which is why flood.zig counts empty records too.

    What the blanket reason was hiding is the part worth keeping. Three
    cases were declined as "0-RTT: deferred pending a replay analysis"
    and not one of them is blocked on that decision:
    `SkipEarlyData-SecondClientHelloEarlyData-TLS13` is a §4.1.2
    argument we now win one message earlier than BoringSSL does and is
    marked KEEP; `TLS13-DuplicateTicketEarlyDataSupport` is a duplicate
    extension we already refuse, differing only in the alert, and is
    finding 15; and `SkipEarlyData-HRR-FatalAlert-TLS13` is about how
    the shim ends a connection after a peer's alert, and is finding 16.
    A reason that
    covers a family stops being read case by case, which is exactly when
    it starts covering things it does not describe.

15. **A duplicate extension earns one alert, not two.**
    `TLS13-DuplicateTicketEarlyDataSupport` sends a NewSessionTicket
    carrying `early_data` twice and wants illegal_parameter; we answer
    decode_error, and mean to.

    We refuse the ticket — the error is `DuplicateExtension`, which is
    what the case maps `:DUPLICATE_EXTENSION:` to — so the whole
    disagreement is one alert on one case.

    §4.2 is a single sentence covering "a given extension block" and
    names no alert for breaking it. §6.2 admits both readings: it is
    decode_error if "there MUST NOT be more than one" is part of the
    block's syntax, and illegal_parameter if it is a message that
    "conform[s] to the formal protocol syntax but [is] otherwise
    incorrect". The RFC does not decide it, so an implementation does.

    Ours is decided by a constraint the RFC does not have: zssl returns
    errors and leaves alerting to the embedder. One rule, enforced by
    one pre-pass over every block we read (finding 9), is one error —
    and an error is the whole of what the library says. Answering two
    alerts would mean carrying two error names for one sentence of §4.2,
    which is API surface bought for a single case, and it would put
    "which message was it in?" into an embedder's alert table.

    BoringSSL's split is not principled either, and reading it is what
    settled this. A duplicate in a ClientHello or ServerHello fails
    inside `tls1_check_duplicate_extensions` during the parse, which
    reports `SSL_R_CLIENTHELLO_PARSE_FAILED` and sends decode_error; a
    duplicate anywhere else fails in `ssl_parse_extensions`
    (`ssl/handshake.cc`), which sets `SSL_AD_ILLEGAL_PARAMETER` under
    the comment "Duplicate ext_types are forbidden". Same violation, two
    answers, chosen by which function happened to catch it. Their own
    corpus asks for both — decode_error in
    `DuplicateExtensionClient-TLS-TLS13` and `-Server-`,
    illegal_parameter here — and we satisfy the two and not the one,
    which is a majority worth naming honestly rather than leaning on: it
    is two against one.

16. **FIXED — the shim waited for a peer that had already given up.**
    `SkipEarlyData-HRR-FatalAlert-TLS13` sends a ClientHello, then a
    fatal handshake_failure, then early data. The library read the alert
    and answered `PeerAlert`, which is right and was right all along.
    The shim then hung, and the case failed on the runner's read
    deadline rather than on anything either side did.

    `Pump.abort` drained the socket before closing whether or not it had
    written an alert. Draining is what makes the close a FIN rather than
    a reset, so that a peer can actually read the alert we just sent —
    and with no alert written there is nothing for it to protect. That
    is the whole justification, and it covers every error reaching the
    branch: a ceiling of our own like `TooManyRecords` gets there too,
    with the peer still mid-send, and an unannounced close is the right
    answer there as well.

    Where it *was* the peer that had stopped, draining did active harm.
    It had sent a fatal alert and was waiting for us to close; we were
    waiting to read; the drain blocked until the other side's deadline
    fired. Two ends waiting to read.

    Worth recording because of where the bug was: not in the library,
    which returned the error the case wanted, but in the embedder's
    error path. `tlsfuzzer/server.zig` — the same mapping written later
    and kept separate on purpose — already had it right
    (`alertFor(err) orelse return err`). The separation that stops two
    harnesses from agreeing by sharing code also let one of them keep a
    fault the other had fixed, and only a case that exercised the exact
    ordering found it.

    `:SSLV3_ALERT_HANDSHAKE_FAILURE:` also needed an `ErrorMap` entry.
    zssl's `PeerAlert` does not carry which alert arrived, so the map
    already points several of BoringSSL's alert-specific errors at it;
    this is one more of the same, not a new kind of imprecision
    (finding 6 records the limitation).

    Reviewing this turned up an asymmetry beside it, since closed. The
    shim's `linger` drained and left the FIN to the connection's own
    `defer close`, while `tlsfuzzer/server.zig`'s `drainBeforeClose`
    half-closes with `shutdown(.send)` *first* — which that harness
    needed for a real race, a peer waiting to see our FIN before sending
    its trailing bytes (docs/TLSFUZZER.md). Draining alone is only half
    an answer: it stops our close from resetting the peer, but a peer
    waiting on our FIN waits as long as we are willing to read. The TCP
    is the same for both harnesses and they had no business differing
    about it, so `linger` half-closes now too.

    No case moved — BoGo has not shaped one that needs it, which is why
    the difference survived this long. It is fixed on the argument
    rather than on a red run, and that is the honest description: the
    other harness had already paid for this lesson.

17. **FIXED — `PeerAlert` never said which alert**, and a case had been
    passing on that.

    zssl reports that the peer sent a fatal alert and, until now, never
    which one: a Zig error carries no payload, so an embedder that
    wanted to log or re-map the peer's refusal had nothing to read.
    Finding 6 recorded that as a limit five findings ago. Both machines
    now keep the description byte in `peer_alert` — the wire value, not
    an `alert.Description`, because §6 lets a peer send any byte and
    this library names only the ones it uses.

    The ErrorMap is where it showed. Three of BoringSSL's
    alert-specific errors pointed at a bare `zssl:PeerAlert`, so a case
    expecting record_overflow was satisfied by *any* fatal alert. The
    shim now prints the description beside the error name and the three
    entries name it, which is a mapping that can be wrong — the point of
    having one. A fourth, `:BAD_ALERT:`, listed `zssl:PeerAlert` among
    several names and had the same hole; the review traced it as
    unreachable — those cases are caught as `MalformedAlert` or
    `BadAlert` first — and it is removed rather than left resting on
    which entry happens to win.

    It was wrong immediately. `AlertAfterChangeCipherSpec` had been
    counted as passing, and it is a `MaxVersion: VersionTLS12` test: the
    runner rejects our 1.3-only hello with protocol_version long before
    the record_overflow the case is named for, and the coarse mapping
    accepted that. Its name does not carry a version, which is why the
    sweep that declined the rest of the 1.2 family walked past it. It is
    declined now, on the same by-design reason as its siblings.

    So the passing count goes **down** by one, 311 to 310, and the floor
    with it. That is the one direction the floor is not supposed to
    move, so it is worth being exact about why: no behaviour changed
    here, and nothing regressed. A case left the corpus we count,
    which is what declining a case always does — and this one was never
    testing us in the first place. A number that drops because a
    measurement got honest is worth more than the number it replaced.

18. **The 0-RTT accept path gets an adversarial oracle.** Fourteen more
    cases, and until this one the whole feature had only tests its own
    author wrote.

    The shim opts in the way any embedder must: a clock, §8.2's strike
    register, and tickets that advertise `max_early_data_size` — three
    positive answers, because the library refuses early data unless it
    has all three. `-enable-early-data` is what turns them on, and the
    ticket's terms come back through `psk_lookup` so §4.2.10's suite
    check and §8.3's freshness check have something to check against.

    Two things had to exist before the shim could opt in at all, and
    both were found by trying:

    - **§2's 0.5-RTT data.** BoGo's server-side cases set
      `ExpectHalfRTTData` and the runner *blocks reading* those records,
      so a shim that cannot answer before the client's Finished hangs
      every one of them. That was its own slice, and the nonce sequence
      it had to carry across the session handoff was the delicate part.
    - **`HalfRTTTickets: 0`** in the shim config. When 0-RTT is
      accepted the runner first reads that many NewSessionTickets in the
      half-RTT window — BoringSSL sends two — and ours sends none until
      after `connected`. Telling the runner so is what the setting is
      for; the alternative was inventing a ticket schedule to match
      somebody else's.

    One number came from reading their source rather than guessing.
    `TLS13-MaxEarlyData-Server` sends exactly 14337 bytes and expects the
    connection to end, which only happens if the ticket advertised
    BoringSSL's own `kMaxEarlyDataAccepted` of 14336. Their comment says
    why it sits "slightly below" `kMaxEarlyDataSkipped`'s 16384: one is
    plaintext accepted, the other ciphertext discarded, and a server
    that declines should never count less than one that accepts. Our
    skip ceiling was already the second number; the shim now advertises
    the first.

    What the fourteen actually press is worth naming, because it is not
    the happy path. `EarlyData-Server-BadFinished` is the §4.4 transcript
    split — a client Finished that MACs the wrong context, which is the
    bug that would have shipped silently. `SkipEndOfEarlyData`,
    `Server-NonEmptyEndOfEarlyData`, `TrailingMessageData-EndOfEarlyData`
    and `WrongMessageType-EndOfEarlyData` are §4.5's grammar from four
    directions. `PartialEndOfEarlyDataWithClientHello` packs a fragment
    of it against a hello. `TLS13-MaxEarlyData-Server` walks the ceiling.

None of these are exploitable as far as the runner can show; they are
laxity, and laxity is what BoGo exists to find.

19. **The peer's signature algorithm, and §4.4.3's other abort.**
    Twenty-four more cases, from the row this document had been
    calling one of the largest wins available without anyone checking
    what was behind it.

    Two flags, both client-side. `-verify-prefs` narrows what the client
    will accept in a CertificateVerify, which is now
    `ClientHandshake.Config.verify_schemes` — one list, read both by the
    hello that advertises it and by the verifier that enforces it,
    because §4.4.3 makes those the same promise.
    `-expect-peer-signature-algorithm` asks what the server actually
    signed with, which the client had been checking and throwing away; it
    is `peer_signature_scheme` now, the mirror of the server's
    `signature_scheme` that `interop` has always asserted on.

    The library defect underneath: every unrecognised code point in a
    CertificateVerify returned `BadSignature`, whose alert is
    decrypt_error. §4.4.3 asks for illegal_parameter, and the two are not
    interchangeable — one says the peer's key is bad, the other says it
    broke a negotiation, and only the second is true when no signature
    was ever checked. `UnofferedSignatureScheme` is that case, and the
    in-tree test forges both shapes of it: a code point outside the five
    we implement, and a scheme we verify perfectly well that the embedder
    withheld. The second is the one that proves `verify_schemes` is
    enforced rather than merely advertised.

    A resumption wrinkle worth recording, because it is a seam rather
    than a bug. BoGo asserts the algorithm on *both* exchanges, and a
    resumed TLS 1.3 handshake carries no CertificateVerify — so the
    library reports null and the shim remembers. That is the right split:
    the scheme is a property of the session, and sessions are the
    embedder's, exactly as tickets are.

    Five cases stay declined and are marked KEEP, not fixed.
    `Client-VerifyDefault-` over Ed25519, P-521 and the three ML-DSA
    sizes pair an unsupported *key type* with an unsupported *signature
    scheme*, and we notice the key first: those leaves are certificates
    we cannot use under any scheme we offer, so they earn bad_certificate
    — or, for ML-DSA, decode_error, because std's certificate parser will
    not read them at all. BoGo wants illegal_parameter for all five. The
    divergence is about *where* we notice, not whether we refuse, and the
    §4.4.3 abort this finding added is what fires when the scheme really
    is the only thing wrong.

    Twenty-nine more were declined for their version. They are the same
    accident finding 18's `-curves` note describes: the runner sets
    MaxVersion on its own Config rather than passing the shim a flag, so
    nothing on the wire says a case is pre-1.3, and these had been held
    back only by the two flags this finding added.

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
