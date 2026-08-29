# tlsfuzzer — wired

[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) is a TLS client
written in Python over tlslite-ng: a third implementation, by different
people, from the one BoGo brings. It is the natural complement to BoGo
here because it drives a **server** — one script opens hundreds of TCP
connections, runs a scripted conversation down each, and scores them
itself.

It runs: `zig build tlsfuzzer`.

```
tlsfuzzer: 17 scripts to run, 40 disabled (0 of those untriaged)
tlsfuzzer: 17 scripts passed, 0 failed, 40 disabled, floor 17
tlsfuzzer: PASS
```

Read the second number on the first line before anything else. This gate
is thin, and the rest of this file is about how thin, and why.

## How it is wired

- **`tlsfuzzer/server.zig`** — the server under test. A long-lived
  listener rather than a per-case binary: it never dies on a failing
  connection (most of tlsfuzzer's conversations are *meant* to fail), it
  **echoes application data back byte for byte**, and it answers a
  close_notify with a close_notify because the scripts' `ExpectAlert`
  requires one — BoGo's open finding 6 seen from the other side. It keeps
  a ticket across connections so the resumption scripts have something to
  return with.
- **`tlsfuzzer/run.zig`** — the gate. Fetches the pinned tlsfuzzer commit
  into `zig-out/tlsfuzzer/`, builds a virtualenv holding tlsfuzzer's own
  pinned tlslite-ng, starts **one harness per leaf**, runs the scripts,
  and holds the result against a floor. Exit 0 passed, 1 failed, 2 could
  not run — the same convention as the other two gates.
- **`tlsfuzzer/scripts.json`** — `Run` lists what the gate drives, each
  entry naming the leaf it wants; `Disabled` maps every other script to
  the one-line reason it is not run.

## Two leaves

The gate serves an ECDSA leaf on port 4433 and an RSA one on 4434, and
each `Run` entry says which it connects to (`"leaf": "rsa"`; ECDSA is the
default).

That is not a nicety. A dozen-odd scripts advertise **only** RSA-PSS
signature algorithms — `test_tls13_ccs.py` asks for `rsa_pss_rsae_sha256`
and `rsa_pss_pss_sha256` and nothing else — and a server holding an ECDSA
leaf can answer them with nothing but `handshake_failure`. That fails the
script's own `sanity` conversation, and every case queued behind it, for
a reason that has nothing to do with the code under test. Six scripts
were sitting in `Disabled` on those grounds, five of them recorded as
"not yet triaged", and all six pass outright once asked over a leaf they
can verify.

The tell was `sanity` appearing in the FAILED list. A script whose
trivial baseline conversation fails is not reporting on the protocol; it
is reporting on the fixture.

## The numbers, and the debt

**17 of 57** `test-tls13-*` scripts run, 1334 conversations between them.
`test-tls13-lengths` is 1002 of those on its own: every plaintext length
from 1 to 2^14, each echoed back and checked for size.
`test-tls13-connection-abort` is another 150, aborting the connection at
every point in the handshake and checking the server neither hangs nor
crashes, and `test-tls13-invalid-ciphers` 52. The rest are the basic
conversation, alert handling encrypted and not, Minerva timing-signal
sanity, HelloRetryRequest and the §9.2 hello that must not get one, empty
and unrecognised cipher lists, record padding, ticket counting, the two
RSA signature scripts, the 68 conversations of `record-layer-limits`
walking §5.1's and §5.2's caps from both sides since finding 7 closed,
and `ccs` since finding 8 did.

**40 disabled, none of them untriaged.** 24 carry scope reasons that were
always plain — client certificates, FFDHE, brainpool curves, EdDSA,
ML-DSA, ML-KEM, 0-RTT, compressed certificates, `psk_ke` without (EC)DHE,
TLS 1.2 fallback, AES-CCM — each pointing at a written decision. The
other 18 said "not yet triaged" for as long as this file has existed;
they now say what they are, and the sweep that got them there is
[the triage](#the-triage-of-the-eighteen) below.

The method that settled the arguable ones is worth naming, because
reading the RFC did not settle them: every disputed script was also run
against **real `openssl s_server`** on the same fixture. A script zssl
fails and OpenSSL passes is a finding; a script both fail is the corpus
stating a policy rather than a requirement. That one oracle produced
findings 7 through 11 below, and turned three scripts that looked like
defects into `Not a defect` with a number behind it —
`shuffled-extentions` and `large-number-of-extensions` score *identically*
under OpenSSL, 2 of 19 and 2 of 22.

One caution about those counts, learned by measuring twice: some scripts
randomise their own vectors, so their pass count moves run to run with
nothing changing underneath. `symetric-ciphers` scored 59, 71, 69 and 75
on one unmodified binary. Its entry names the cause — every failure is an
AES-CCM suite — and deliberately carries no number, because a number that
moves on its own is worse in a ledger than no number at all.

The gate still prints the untriaged number on every run, and it should
stay zero: a suppression ledger where an entry says "unknown" is a debt,
and a debt that is not counted is a debt that is not paid. A new script
arriving with a pin bump may push it back above zero; triage it before
the commit lands, never after.

**The floor** is 17. `scripts.json` can disable a script, but not quietly:
the passing count falls with it and the gate goes red.

## What it cost to get here

Eleven defects, all found by running things rather than reading them, and
each worth recording because each looked like something else. 1 through 3
are the harness's and the gate's; 4 through 8 and 11 are the library's;
9 and 10 are the harness's again, and both were mistaken for the
library's until the OpenSSL oracle said otherwise.

1. **The listener starved.** It is sequential, and tlsfuzzer's abort
   cases deliberately leave sockets that never send again — one held the
   accept loop and every later script failed, which read as a
   corpus-wide failure rather than one stuck connection.
2. **The first fix for that crashed it.** `SO_RCVTIMEO` makes `read`
   return `EAGAIN`, and `std.Io.Threaded` treats `EAGAIN` on a socket it
   believes is blocking as a programmer bug and panics — so the harness
   died mid-sweep and every measurement after it was connection-refused
   noise. A concurrent watchdog that *shuts the socket down* is the fix:
   a blocked read then returns end-of-stream, which every path already
   handles.
3. **The gate hung waiting for its own server.** `readSliceShort` waits
   until its whole buffer is full; the harness prints one `listening`
   line and goes quiet, so the gate waited forever for bytes that never
   come. `interop/main.zig` documents this exact trap on socket reads —
   the same mistake, on a pipe. `fill(1)` then `buffered()` is the idiom.
4. **A remote abort in `ServerHandshake`.** §5.4 allows a zero-length
   `TLSInnerPlaintext.content` for `application_data` and nothing else,
   and both machines took the surviving length straight to
   `assert(payload.len >= 1)` in their alert path. A peer that seals an
   alert record containing only its content-type byte therefore aborted
   the process — in ReleaseSafe too, which is what release builds ship.
   The plaintext path had been guarded at header parse all along (§5.1,
   `record.zig`); the protected path had no equivalent, because the
   length that matters there is the one that survives padding removal
   and only the inner content-type switch can see it. `ClientHandshake`
   had the same hole and was fixed with it. Both now return
   `unexpected_message`, which is what §5.4 asks for.

   It surfaced as the RSA harness dying mid-sweep, which fails every
   script queued behind it — so the *measurement* it broke looked like a
   corpus-wide rejection rather than one crash. The gate now probes each
   harness for liveness after the run and says plainly when one died,
   because that ambiguity is expensive: it cost one full re-sweep to
   notice that two runs of the same corpus disagreed.

5. **Alerts sent under the wrong keys, for a whole round trip.** §4.4.4
   switches the server's write keys to application keys the moment its
   Finished goes out — that is what makes 0.5-RTT data legal — and the
   client installs its application *read* keys as soon as it verifies
   that Finished. zssl staged the secrets at the right point (§7.1, in
   `finishFlight`) but kept sealing with the *handshake* protector until
   the client's Finished arrived, so everything the server sent in that
   window was unreadable by any conforming peer. The window exists to
   send one thing: the refusal of a client Finished that does not
   verify. That alert could never be read.

   It reproduces between zssl's own two machines — the client reports
   `AuthenticationFailed` on the server's alert — so this was never a
   tlslite-ng disagreement. `finishFlight` now moves the send side onto
   the application keys and leaves the receive side on the handshake
   ones, where the client's Finished still lives. Because the session is
   later built from the same secret, `startApplicationKeys` asserts the
   window protector sealed nothing: its only writer is `sendAlert`,
   which retires the machine, so a used one would mean a nonce sequence
   restarting under a live key.

   The blast radius is the reason to record it. Most tlsfuzzer
   conversations *end* by reading the server's alert, so one fix moved
   the whole corpus: `test-tls13-finished` 2 -> 39 passing of 42,
   `symetric-ciphers` 36 -> 78 of 102, `keyupdate` 59 -> 61 of 62,
   `record-layer-limits` 8 -> 12, `zero-length-data` 5 -> 8, and two
   scripts to green outright. A defect that hides behind every other
   failure looks like a corpus that dislikes you.
6. **An omitted `key_share` treated as an empty one.** §4.2.8 lets a
   client send an empty `client_shares` to ask the server to choose a
   group, at the cost of a round trip, and that earns a
   HelloRetryRequest. §9.2 requires the extension to be *present* in any
   hello attempting (EC)DHE, and a server receiving one without it "MUST
   abort the handshake with a `missing_extension` alert". zssl sent a
   retry for both, because `key_share_count == 0` cannot tell them
   apart — the parser now records presence separately.

   The check is deliberately narrow: only a hello carrying
   `supported_groups` *without* `key_share` is the §9.2 case. Neither
   present is a client not offering (EC)DHE at all, which §9.2 does not
   reach, and zssl's refusal of that stays `handshake_failure`.

7. **A handshake message's declared length was never checked against
   its type.** Finished carries `verify_data` and nothing else, so its
   length is the negotiated hash's; KeyUpdate carries one byte. zssl took
   the declared length from the wire and never asked whether the type
   admitted it, so a length no message of that type could have was
   decided by whatever it happened to reach: a zero- or over-length
   KeyUpdate fell out of the `request_update` switch as
   `illegal_parameter`, and a declared length past the reassembly buffer
   was refused as a *capacity* failure, `BufferOverflow`, which the
   harness's table can only call `internal_error`.

   §6.2 is plain about the answer: `decode_error`, "a message could not
   be decoded because some field was out of the specified range **or the
   length of the message was incorrect**". The fix asks the question the
   type already answers, and asks it before capacity, because the two
   are different verdicts and the order decides which one the peer
   hears. `handshake.Assembler` now refuses a declared length the type
   cannot have — `key_update` is one byte by §4.6.3's grammar, `finished`
   is at most the largest hash any suite here negotiates — on four header
   bytes, before a peer can make anyone hold the body it promised. A
   Finished declaring 16 MiB is not a message we lack room for; it is a
   message that cannot exist, and the old answer told the embedder its
   own buffer was too small about a message no buffer would have helped.

   **Then BoGo said no, and it was right to.** The obvious other half of
   this fix — telling a Finished of the wrong *length* from one that does
   not verify, decode_error against decrypt_error — broke
   `TrailingMessageData-TLS13-ServerFinished` and its client twin, which
   want `decrypt_error` and say so with `:DIGEST_CHECK_FAILED:`. The two
   corpora genuinely disagree, and each is reading a real sentence:
   §6.2's rule for lengths, against §4.4.4's "Recipients of Finished
   messages MUST verify that the contents are correct and if incorrect
   MUST terminate the connection with a `decrypt_error` alert". A
   Finished has exactly one field, so its length being wrong *is* its
   contents being incorrect. §4.4.4 is the more specific rule and this
   tree follows it, with BoringSSL; OpenSSL and tlsfuzzer take §6.2.

   That leaves the finding split, and the split is the useful part. The
   length **no hash could be** is settled in the assembler, where the two
   corpora agree and where it costs nothing to decide. The length that
   is merely *not this hash* stays `decrypt_error` at the message, where
   §4.4.4 put it. Shipping only the half both oracles accept is why BoGo
   is still 278 of 278.

   Moved: `test-tls13-record-layer-limits` **66 of 68 -> 68**, and into
   `Run` — the two that remained declared 16380 bytes of Finished, which
   no hash is; and `test-tls13-keyupdate`'s two length cases to green,
   leaving only finding 10's. `test-tls13-finished` stays at 39 of 42 on
   the three §4.4.4 costs us, which is a `KEEP` and not a gap.
8. **A ChangeCipherSpec record's payload was never read.** §5 admits "an
   unencrypted record of type change_cipher_spec **consisting of the
   single byte value 0x01**" inside a stated window, and an
   implementation "which receives any other change_cipher_spec value ...
   MUST abort the handshake with an `unexpected_message` alert". zssl
   bounded how *many* such records it tolerated (`ccs_seen_max`) and
   where (§5's window, both edges, which TLS-Anvil found), and never
   looked at the byte: a record holding `01 01`, or a hundred `01`s, was
   accepted as compatibility filler.

   Two ways to be "any other value" and the corpus sends both — a byte
   that is not 0x01, and more than one byte of it. Neither is a
   ChangeCipherSpec in the 1.2 sense either, because 1.3 keeps the
   record type and drops the message: there is nothing left to parse,
   and the whole grammar is one comparison.

   The check is one comparison and it lives in `record.zig`, beside
   `parseHeader`, because it is the same layer's rule about the same
   peer's bytes — and because both machines had the hole, so both now
   ask the same function rather than each carrying its own copy of the
   sentence. It is asked *before* anything about where the record
   landed: a record that is not the compatibility record is not one
   whose position is worth discussing.

   Moved: `test-tls13-ccs` **4 of 5 -> 5**, and into `Run`;
   `test-tls13-multiple-ccs-messages` 3 -> 4 of 7, where the three that
   remain are its one-CCS policy. Real OpenSSL 3.6.3 scores 2 of 7 on
   that script and fails the very conversation this closed, so §5's MUST
   is one the reference implementation does not keep and we now do.
9. **(harness) A record refused at its header closed the connection
   without an alert, but only after the handshake.** `Pump.converse`
   routed `handleRecord`'s errors through `Pump.abort`, which sends
   whatever the table names — and returned `nextRecord`'s errors raw, to
   a caller that swallowed them and closed. So every header-level refusal
   after `connected` reached the peer as an abrupt close: `RecordOverflow`
   above all, which is the single most-tested refusal in the corpus.
   During the handshake the same path *is* wrapped, by `serve`, which is
   exactly why this hid — the gate's own scripts exercise the guarded
   half.

   zssl's answer was right the whole time. §5.1's cap is enforced at
   header parse in `record.zig`, where CLAUDE.md's invariant says it
   must be, and the harness threw the verdict away. Routing that path
   through `abort` too took `test-tls13-record-layer-limits` from **16 of
   68 to 66**, past OpenSSL's 62 on the same script — one line, fifty
   conversations. A library that refuses correctly and a harness that
   reports it as silence are indistinguishable from a library that does
   not refuse, which is the reason to record a harness bug at the same
   weight as a library one.
10. **(harness) The echo answers every record; the scripts expect one
    reply.** `converse` echoes each application-data record as it
    arrives, which is what `test-tls13-lengths` needs — 1002
    conversations each checking the reply's *length* against what they
    sent. Several other scripts split one request across three records
    and then wait for a single response, and read our second echo where
    they expected an alert or a ticket. Real `s_server -www` answers
    once and passes all of them.

    Costs `test-tls13-zero-length-data` (3 of 11),
    `test-tls13-zero-content-type` (2 of 8) and one conversation of
    `test-tls13-keyupdate`. It is a genuine tension rather than an
    oversight — `lengths` and these want opposite things from the same
    loop — and it is recorded so the next reader does not spend the
    afternoon we spent proving it was not a record-layer bug.
11. **`ClientHello.legacy_version` is ignored, not policed.** §4.2.1 is
    unambiguous that a server "MUST NOT use the ClientHello.legacy_version
    value for version negotiation" once `supported_versions` is present,
    and zssl does not — it never reads the field. §4.1.2 is equally
    unambiguous that the client "MUST" set it to 0x0303, and the two
    together leave open whether a server should *refuse* a value that
    cannot be conformant.

    tlsfuzzer says yes, and real OpenSSL agrees with it 9 times out of
    10: both answer `protocol_version` to a hello whose legacy_version is
    below 0x0300, where zssl proceeds to a ServerHello. Enforcing
    `== 0x0303` would take `test-tls13-legacy-version` from 2 of 10 to
    10 — stricter than OpenSSL, which still accepts (3,0) — and costs
    nothing at interop, because every implementation that speaks 1.3
    sends 0x0303. Recorded as a gap rather than closed because the
    argument runs both ways and §4.2.1's "MUST" is the louder of the two.

Five of the eleven were the harness's or the gate's — three at the start,
and 9 and 10 found here, both of which read as library defects until the
oracle disagreed. The other six are the library's. None of the eleven
would have been visible to a gate that was only read.

## The triage of the eighteen

What the 18 turned out to be, once each was run against both leaves and
then against real OpenSSL. Full reasons live in `scripts.json`; this is
the shape of the debt that was paid.

| Verdict | Scripts |
| --- | --- |
| **OPEN GAP** — a defect we mean to fix | `legacy-version` (11) |
| **SCOPE** — needs a capability or a fixture we chose not to carry | `ecdhe-curves`, `ecdsa-support`, `psk_dhe_ke`, `rsapss-signatures`, `serverhello-random`, `session-resumption`, `signature-algorithms` |
| **KEEP** — we refuse the input and differ only in the alert, having argued ours | `finished` (7, with BoGo) |
| **Green, and now in `Run`** | `record-layer-limits` (findings 9 and 7), `ccs` (finding 8) |
| **Not a defect** — the corpus is stating its own policy, or the harness's shape | `keyupdate`, `keyupdate-from-server`, `large-number-of-extensions`, `multiple-ccs-messages`, `shuffled-extentions`, `zero-content-type`, `zero-length-data` |

Two patterns are worth carrying forward. The **SCOPE** column is mostly
fixtures, not protocol: `ecdsa-support` wants a P-384 and a P-521 leaf,
`rsapss-signatures` wants a certificate whose key is `id-RSASSA-PSS`, and
`psk_dhe_ke` wants `--psk`/`--psk-iden` on the harness to seed
`psk_lookup` with an out-of-band key. Three leaves and two flags would
move five scripts, and none of that is protocol work.

And every **Not a defect** in the table is a number, not an opinion:
`shuffled-extentions` and `large-number-of-extensions` score identically
under OpenSSL, `multiple-ccs-messages` scores *worse* under OpenSSL than
under zssl, and `keyupdate-from-server` fails under both. A ledger entry
that says "we disagree with the corpus" is worth what the measurement
behind it is worth.

## Timing

A warm run is about **44 seconds**, and 35 of those are
`test-tls13-lengths` walking 1002 conversations from one byte to 2^14.
Everything else together is under ten: `connection-abort`'s 150
conversations take 0.81 s. A cold run adds a `git clone` and a virtualenv
with two pip installs, which is the minute or so, and both are cached in
`zig-out/tlsfuzzer/` afterwards.

Worth the 35 seconds: those conversations are the only coverage the
record layer gets across every legal plaintext length, and the §5.4 cap
that BoGo's open finding 3 says is missing lives in exactly that path.
The gate ran in 2.5 s before `lengths` could run at all.

## Running it

```sh
zig build tlsfuzzer                          # the gate
zig build tlsfuzzer-server -- --port 4433    # the server alone, to hand-drive
```

With the server running, any script in the pinned checkout can be pointed
at it — which is how the 18 untriaged entries get triaged:

```sh
cd zig-out/tlsfuzzer/tlsfuzzer
PYTHONPATH=. ../venv/bin/python scripts/test-tls13-finished.py -h localhost -p 4433
```

The harness takes `--port`, `--cert`, `--key`, `--alpn` and `--tickets`;
`--tickets 0` is a legitimate configuration and some scripts want it.
Triage every script against **both** leaves before drawing a conclusion —
the RSA one is what the gate serves on 4434:

```sh
zig build tlsfuzzer-server -- --port 4434 \
    --cert src/testdata/rsa2048-cert.pem --key src/testdata/rsa2048-key.pem
```

And check the harness is still alive afterwards. A crashed one fails
every later script for a reason that is not theirs, and a sweep taken
across a crash is worse than no sweep: it reads like data.

## Moving the pin

Change `tlsfuzzer_commit` in `tlsfuzzer/run.zig`, run the gate, and
expect it to go red — new scripts arrive failing. Triage each into a fix
or a `scripts.json` entry, then re-derive `passing_floor` in the same
commit. A pin bump that does not touch the floor has either learned
nothing or hidden something.
