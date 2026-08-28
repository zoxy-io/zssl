# BoGo — wired

BoGo is BoringSSL's adversarial TLS test runner: a Go program that plays
a deliberately hostile peer and drives an implementation through some
thousands of cases, most of which are things a correct stack must
*refuse*. It is the highest-value item on zssl's assurance ladder,
because every other oracle in the tree tests what we accept.

It now runs: `zig build bogo`.

```
bogo: 261 passed, 0 failed, 6918 declined by the shim (89), floor 261
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

**274 passed.** Cases the runner ran end to end and we satisfied —
including the alert we sent, which BoGo checks by name. 143 drive
`ClientHandshake` and 131 drive `ServerHandshake`. The server number was
6 until RSA signing landed, 100 until secp256r1/secp384r1 did, 110 until
§9.2's `missing_extension` did, 111 until §5.4's inner-plaintext cap did,
113 until eight suppressions turned out to be describing bugs that were
already fixed, 121 until finding 8 was taken apart, 124 until §4.2.9's
psk_key_exchange_modes was enforced, 127 until §4.2's duplicate rule
did, and 128 until §4.2.11's binder rules were told apart. The client
number was 121 until §4.2's unsupported_extension landed, 134 until
finding 4's flood ceilings did, 136 until finding 5 stopped refusing
`user_canceled`, 139 until that same duplicate rule, 140 until finding 6
split the close in two, and 141 until finding 7 read the ticket's
extension block; see below.

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

Twelve more were open. Nine are fixed outright — 2, 3, 4, 5, 6, 7, 9, 10
and 12 — and four still carry ledger entries, 12 suppressed cases
between them: 4 under finding 1, 5 under 10, 2 under 8 and 1 under 11.
Only one of those four is a gap in the sense the word implies — finding
1, the packed post-handshake record. 8 is down to two divergences we
intend to keep, 11 is a documented non-defect, and finding 10's
remaining 5 are a scope decision filed under its number rather than an
open defect, which is why a fixed finding still has entries.
All twelve keep their numbers rather than being renumbered, because the
ledger cites them by number.

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

   Four cases now, not three. `Shutdown-Shim-KeyUpdate-TLS-Sync-`
   `PackHandshake` joined when finding 6 made the shim read after its
   own close_notify instead of returning: the case was passing because
   nothing looked at it, and looking found this gap rather than a new
   one. Its `-TLS-Sync` and `-SplitHandshakeRecords` siblings still
   pass, which is what isolates the cause to packing rather than to the
   shutdown path.
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
   translation: zssl reports *that* the peer sent a fatal alert and
   never *which*, so an embedder needing the description does not have
   it.
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

    The other 5 are the `-SecondBinder` variants, and they are not a
    defect at all: that suffix forces a HelloRetryRequest
    (`resumption_tests.go`, "Force a HelloRetryRequest by predicting an
    empty curve list"), so the corrupt binder rides the *second*
    ClientHello, and `selectPsk` ignores PSK offers on a retry hello on
    purpose — the binder there hashes the §4.4.1 surgery transcript,
    which zssl does not carry. Their ledger entries say that now, rather
    than pointing at an OPEN GAP that is closed; they move again if the
    HRR+PSK path is ever carried.

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
