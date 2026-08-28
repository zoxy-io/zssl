# tlsfuzzer — harness wired, gate blocked

[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) is a TLS client
written in Python over tlslite-ng: a third implementation, by different
people, from the one BoGo brings. It is the natural complement to BoGo
here, because it drives a **server** — one script opens hundreds of TCP
connections, runs a scripted conversation down each, and scores them
itself.

`tlsfuzzer/server.zig` is that server, and it works. What does **not**
exist is a gate: no `zig build tlsfuzzer`, no floor, no CI job, no
badge. This file explains why, because the reason is a measurement and
not an omission.

## Why there is no gate yet

tlsfuzzer's TLS 1.3 scripts overwhelmingly hardcode **secp256r1**:

| | |
| ---: | --- |
| 57 | `test-tls13-*` scripts in the corpus |
| 48 | that never mention x25519 at all |
| 2 | that expose a `-g` flag to choose the group |

zssl offers x25519 and nothing else (DESIGN.md §1), so a client whose
ClientHello carries a secp256r1 key share *and* a secp256r1-only
supported_groups list gets `handshake_failure`. That is correct
behaviour, and it makes nearly the whole corpus inapplicable as written.

Of the two scripts that take `-g x25519`:

```
test-tls13-conversation      PASS: 3   FAIL: 0
test-tls13-ecdsa-support     PASS: 5   FAIL: 5   (wants P-256/384/521 certificates)
```

So a gate built today would gate on one script. `docs/BOGO.md` argues at
length that a runner reporting green over a sliver of its corpus is
worse than no runner, because it reads like coverage. The same argument
applies here to the same standard, so the gate waits.

**The blocker is one library change, and it is not tlsfuzzer's alone.**
BoGo declines 208 cases for exactly this reason — "a group that is not
x25519". Adding secp256r1 and secp384r1 key exchange unlocks both at
once, which is why it is the next slice rather than a curiosity.

## What the harness does

`tlsfuzzer/server.zig` is a long-lived listener, not a per-case binary:

- It **never dies on a failing connection**. Most of tlsfuzzer's
  conversations are meant to fail; a harness that exits on the first
  refusal scores one case and hangs the rest.
- It **answers application data**, because the scripts send
  `GET / HTTP/1.0` and wait for bytes back.
- It **answers a close_notify with a close_notify**, which the scripts'
  `ExpectAlert` requires. This is BoGo's open finding 6 seen from the
  other side, and it is only expressible because `ServerHandshake.sendAlert`
  is callable after the peer has closed its direction — §6.1's
  half-close.
- It keeps a ticket across connections, so the resumption scripts have
  something to come back with.

Two defects turned up in the harness itself, both by running it rather
than reading it:

1. **It blocked forever on abandoned connections.** The listener is
   sequential, and tlsfuzzer's abort cases deliberately leave sockets
   that never send again — one of those held the accept loop and starved
   every later script, which looked exactly like a corpus-wide failure.
   Each connection now carries an `SO_RCVTIMEO` deadline.
2. **It answered `GET /` with nothing** until the HTTP reply was added,
   which the scripts read as a truncated conversation.

## Running it by hand

The harness is useful today for exactly the kind of thing it was built
for — pointing a hostile client at the server and watching what happens.

```sh
# One terminal: the server under test.
zig build tlsfuzzer-server -- --port 4433

# Another: a pinned tlsfuzzer, in a virtualenv.
git clone https://github.com/tlsfuzzer/tlsfuzzer && cd tlsfuzzer
python3 -m venv venv && venv/bin/pip install 'ecdsa>=0.15' 'tlslite-ng==0.9.0b2'
PYTHONPATH=. venv/bin/python scripts/test-tls13-conversation.py \
    -h localhost -p 4433 -g x25519
```

The harness takes `--port`, `--cert`, `--key`, `--alpn` and `--tickets`;
`--tickets 0` is a legitimate configuration and some scripts want it.

## What it would take to finish

In order:

1. **secp256r1 and secp384r1 key exchange** — the blocker, and worth
   208 BoGo cases besides.
2. A `tlsfuzzer/run.zig` gate in the shape of `bogo/run.zig`: pin the
   checkout by commit, build a virtualenv, run a curated script list,
   hold the result against a floor, exit 2 as a readable SKIP with no
   Python.
3. A `scripts.json` carrying per-script arguments and a one-line reason
   for every script or conversation excluded — tlsfuzzer's own
   `tests/tlslite-ng.json` is the format to follow, `-e <conversation>`
   and all.
4. A CI job, and only then a badge.

Until step 1 lands, the honest count for this runner is one script, and
that is what this file says.
