# TLS-Anvil — wired

[TLS-Anvil](https://github.com/tls-attacker/TLS-Anvil) derives its test
cases from the text of 14 RFCs and combines them pairwise, rather than
collecting cases an implementation once got wrong. That is why it is
here: BoGo is BoringSSL's own regression corpus and tlsfuzzer is
hand-written attack scripts, so both are shaped by what their authors
already suspected. A corpus generated from requirements is wrong in
different places, and different is the whole value of a third oracle.

It runs: `zig build tlsanvil`.

```
tlsanvil: 115 passed, 0 failed, 1 suppressed, 321 disabled of 437 tests, floor 115
tlsanvil: PASS
```

## How it is wired

- **The pin is an image digest**, not a tag. TLS-Anvil ships as a
  container and `:latest` is a moving target; a gate whose corpus can
  change underneath it measures nothing. Moving the pin means moving
  `tlsanvil_digest` and re-deriving the floor in the same commit.
- **The server under test is `tlsfuzzer/server.zig`** — the same
  long-lived, echoing listener the tlsfuzzer gate drives. TLS-Anvil wants
  exactly that shape, and a third harness would be a third thing to keep
  correct. It is reached at `host.docker.internal`, because the harness
  runs on the host and the corpus runs in a container.
- **`tlsanvil/run.zig`** starts the harness, runs the container, reads
  the report, and holds the passing count against a floor. Exit 0
  passed, 1 failed, 2 could not run — the same convention as the other
  gates, where 2 here means no reachable Docker daemon.

## It scopes itself

Its ledger is nearly empty, and not because we are lenient: of 437 tests,
**321 disable themselves**. Client-side cases
opt out against a server ("TestEndpointMode doesn't match") and TLS 1.2
and DTLS cases opt out against a 1.3-only peer ("ProtocolVersion of the
test is not supported by the target"). That count comes from the tool,
the way BoGo's exit-89 declines do, rather than from a file we maintain
— which also means it will move on its own if the pin moves, and the
floor is what notices.

## The numbers

**115 passed** of the 116 that actually run, across ~800 individual test
cases. **321 disabled**, as above. **1 suppressed**, with a written
reason, in `tlsanvil/tests.json`:

- **`ClientHello.invalidLegacyVersion_ssl30`** wants a fatal alert for a
  ClientHello whose `legacy_version` is 0x0300. §4.2.1 says the opposite:
  with `supported_versions` present a server "MUST NOT use the
  ClientHello.legacy_version value for version negotiation and MUST use
  only the 'supported_versions' extension", and aborting is a MAY
  reserved for `legacy_version` 0x0304 or later. zssl enforced a legacy
  version field once already and it refused real clients sending 0x0300
  — docs/BOGO.md, finding 4. So this one is declined, not fixed.

The ledger keys on `<class>.<method>`, not on TLS-Anvil's test ids. Those
ids look stable and are not: the same failures carried different ids
across runs once the tree changed underneath them. An early draft of this
document claimed otherwise, which would have made the ledger stop
matching without saying so.

## What it cost to get here

Three defects and one harness artefact, all found before the gate landed.

1. **A remote panic on an empty application_data record.** §5.1 lets an
   application_data record be empty on the wire, and `record.parseHeader`
   implements exactly that. `handleProtectedRecord` then asserted the
   record was longer than its own header, so five bytes from a connected
   peer aborted the server. Hit 51 tests into the first exploratory run.
2. **`psk_key_exchange_modes` framing was not checked.** §4.2.9's grammar
   is `psk_key_exchange_modes<1..255>`, and a length disagreeing with its
   contents was read by `offersPskDheKe` as "no mode offered" rather than
   refused — a malformed hello became an ordinary handshake. Checked at
   parse now. The semantics of that same extension had been hardened
   hours earlier; the framing around them had not.
3. **ChangeCipherSpec was accepted outside §5's window.** The rule is
   explicit — "before the first ClientHello message or after the peer's
   Finished message, it MUST be treated as an unexpected record type" —
   and the code's own comment said "ignored wherever it lands". Both
   machines now refuse outside the window and still drop D.4's
   compatibility record inside it.

And the artefact, which is the more useful lesson:

**The harness's own deadline was making zssl look stricter than it is.**
`tlsfuzzer/server.zig` killed a connection after five seconds — right for
tlsfuzzer, whose abort cases need it — but TLS-Anvil is a JVM under
emulation, and a legitimate KeyUpdate conversation outran it. That
arrived as "Socket was closed" and read exactly like a protocol failure.
Worse, it was *hiding* defects 2 and 3: the socket closed before the
corpus could observe that we had accepted the record, so two tests were
passing for the wrong reason. The budget is a flag now; tlsfuzzer keeps
five seconds and TLS-Anvil gets thirty.

The first run also sat for 46 minutes talking to a server that had
already aborted, which is why a liveness task polls the harness every 15
seconds and the "harness died" verdict prints *before* the counts. A
corpus that ran against a corpse reports a low number that looks exactly
like a corpus that refused us.

## Timing

About **12 minutes** on an arm64 host, where the amd64 image runs under
emulation; native amd64 is faster. That makes this the slowest gate by a
wide margin, which is why its workflow skips runs that touch only
documentation.

## Running it

```sh
zig build tlsanvil                           # the gate
zig build tlsfuzzer-server -- --port 4435    # the harness alone, to hand-drive
```

With the harness running, the container can be pointed at it directly —
which is how a failure gets diagnosed before it is fixed or written
down:

```sh
docker run --rm --platform linux/amd64 \
    --add-host=host.docker.internal:host-gateway -v "$PWD/out":/output \
    ghcr.io/tls-attacker/tlsanvil@sha256:a8a4bb92... \
    -disableTcpDump -parallelHandshakes 1 -strength 1 -prettyPrintJSON \
    -outputFolder /output/results server -connect host.docker.internal:4435
```

`results/report.json` carries the counts and `results/result_map.json`
maps each result bucket to test ids. Resolve those ids through
`results/results/<id>/_testRun.json`, which names the class, the method,
the RFC requirement, and the parameter combination that induced the
failure — the ids themselves are not stable and are no use as a key.

## Moving the pin

Change `tlsanvil_digest` in `tlsanvil/run.zig`, run the gate, and expect
it to go red — a newer corpus arrives with new cases. Triage each into a
fix or a written reason, then re-derive `passing_floor` in the same
commit. A pin bump that does not touch the floor has either learned
nothing or hidden something.
