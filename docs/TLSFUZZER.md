# tlsfuzzer — wired

[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) is a TLS client
written in Python over tlslite-ng: a third implementation, by different
people, from the one BoGo brings. It is the natural complement to BoGo
here because it drives a **server** — one script opens hundreds of TCP
connections, runs a scripted conversation down each, and scores them
itself.

It runs: `zig build tlsfuzzer`.

```
tlsfuzzer: 10 scripts to run, 47 disabled (26 of those untriaged)
tlsfuzzer: 10 scripts passed, 0 failed, 47 disabled, floor 10
tlsfuzzer: PASS
```

Read the second number on the first line before anything else. This gate
is thin, and the rest of this file is about how thin, and why.

## How it is wired

- **`tlsfuzzer/server.zig`** — the server under test. A long-lived
  listener rather than a per-case binary: it never dies on a failing
  connection (most of tlsfuzzer's conversations are *meant* to fail), it
  answers `GET / HTTP/1.0` with a small HTTP response because the scripts
  wait for bytes back, and it answers a close_notify with a close_notify
  because the scripts' `ExpectAlert` requires one — BoGo's open finding 6
  seen from the other side. It keeps a ticket across connections so the
  resumption scripts have something to return with.
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

**10 of 57** `test-tls13-*` scripts run, 238 conversations between them.
`test-tls13-connection-abort` is 150 of those on its own: it aborts the
connection at every point in the handshake and checks the server neither
hangs nor crashes. `test-tls13-invalid-ciphers` is another 52. The rest
are the basic conversation, an unencrypted-alert case, Minerva
timing-signal sanity, HelloRetryRequest, empty and unrecognised cipher
lists, record padding, and the two RSA signature scripts.

**47 disabled, and 26 of them say "not yet triaged".** That is a debt,
not a result. 21 carry real scope reasons — client certificates, FFDHE,
brainpool curves, EdDSA, ML-DSA, ML-KEM, 0-RTT, compressed certificates,
`psk_ke` without (EC)DHE — each pointing at a written decision. The
other 26 are scripts that run against the harness and fail some or all
of their conversations, and nobody has yet worked out whether each is a
scope decision or a defect. The ledger records the counts observed and
which leaf produced them, so they can be triaged rather than
rediscovered.

The gate prints the untriaged number on every run for that reason: a
suppression ledger where most entries say "unknown" is a debt, and a debt
that is not counted is a debt that is not paid. Triaging those 26 is the
next work here, and it has already produced one finding — see 4 below —
the way BoGo's first run did.

**The floor** is 10. `scripts.json` can disable a script, but not quietly:
the passing count falls with it and the gate goes red.

## What it cost to get here

Four defects, all found by running things rather than reading them, and
each worth recording because each looked like something else. The first
three are the harness's and the gate's; the fourth is the library's, and
is the first finding this oracle produced.

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

The first three were not library defects. The fourth is, and none of the
four would have been visible to a gate that was only read.

## Timing

A warm run is about **2.5 seconds**; the scripts are trivially fast, with
`connection-abort`'s 150 conversations taking 0.81 s. A cold run adds a
`git clone` and a virtualenv with two pip installs, which is the minute
or so, and both are cached in `zig-out/tlsfuzzer/` afterwards. In CI the
setup dominates and the corpus does not.

## Running it

```sh
zig build tlsfuzzer                          # the gate
zig build tlsfuzzer-server -- --port 4433    # the server alone, to hand-drive
```

With the server running, any script in the pinned checkout can be pointed
at it — which is how the 26 untriaged entries get triaged:

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
