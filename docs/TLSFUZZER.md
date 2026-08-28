# tlsfuzzer — wired

[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) is a TLS client
written in Python over tlslite-ng: a third implementation, by different
people, from the one BoGo brings. It is the natural complement to BoGo
here because it drives a **server** — one script opens hundreds of TCP
connections, runs a scripted conversation down each, and scores them
itself.

It runs: `zig build tlsfuzzer`.

```
tlsfuzzer: 4 scripts to run, 53 disabled (31 of those untriaged)
tlsfuzzer: 4 scripts passed, 0 failed, 53 disabled, floor 4
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
  pinned tlslite-ng, starts the server, runs the scripts, and holds the
  result against a floor. Exit 0 passed, 1 failed, 2 could not run — the
  same convention as the other two gates.
- **`tlsfuzzer/scripts.json`** — `Run` lists what the gate drives;
  `Disabled` maps every other script to the one-line reason it is not.

## The numbers, and the debt

**4 of 57** `test-tls13-*` scripts run, 160 conversations between them.
`test-tls13-connection-abort` is 150 of those on its own: it aborts the
connection at every point in the handshake and checks the server neither
hangs nor crashes. The other three are the basic conversation, an
unencrypted-alert case, and Minerva timing-signal sanity.

**53 disabled, and 31 of them say "not yet triaged".** That is a debt,
not a result. 22 carry real scope reasons — client certificates, FFDHE,
brainpool curves, EdDSA, ML-DSA, ML-KEM, 0-RTT, compressed certificates,
`psk_ke` without (EC)DHE — each pointing at a written decision. The
other 31 are scripts that run against the harness and fail some or all
of their conversations, and nobody has yet worked out whether each is a
scope decision or a defect. The ledger records the counts observed, so
they can be triaged rather than rediscovered.

The gate prints the untriaged number on every run for that reason: a
suppression ledger where most entries say "unknown" is a debt, and a debt
that is not counted is a debt that is not paid. Triaging those 31 is the
next work here, and it is likely to produce findings the way BoGo's first
run did.

**The floor** is 4. `scripts.json` can disable a script, but not quietly:
the passing count falls with it and the gate goes red.

## What it cost to get here

Three defects in the harness and the gate, all found by running them
rather than reading them, and each worth recording because each looked
like something else:

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

None of the three were library defects, and none would have been visible
to a gate that was only read.

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
at it — which is how the 31 untriaged entries get triaged:

```sh
cd zig-out/tlsfuzzer/tlsfuzzer
PYTHONPATH=. ../venv/bin/python scripts/test-tls13-finished.py -h localhost -p 4433
```

The harness takes `--port`, `--cert`, `--key`, `--alpn` and `--tickets`;
`--tickets 0` is a legitimate configuration and some scripts want it.

## Moving the pin

Change `tlsfuzzer_commit` in `tlsfuzzer/run.zig`, run the gate, and
expect it to go red — new scripts arrive failing. Triage each into a fix
or a `scripts.json` entry, then re-derive `passing_floor` in the same
commit. A pin bump that does not touch the floor has either learned
nothing or hidden something.
