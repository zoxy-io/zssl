#!/usr/bin/env python3
"""Pair the two harnesses' JSON-lines output and print the comparison.

Reads one file per implementation, matches scenarios by name (through the
alias table below where the two libraries' public APIs make the natural
names differ), and prints ratios. Nothing here computes a verdict: it
formats what the two harnesses measured, and the ratio column says which
way and by how much.
"""

import argparse
import json
import sys

# Where the two harnesses measure the same work under different names.
#
# zssl's handshake always negotiates AES-128-GCM — the client's offer list
# and the server's preference order are both fixed in the library, so the
# other two suites cannot be reached through a connected pair at all. What
# `record_*` measures instead is the record layer directly: one seal and
# one open of a 16 KiB record, which is exactly the work rustls's
# `transfer_*` does over its connection. The pairing is only honest
# because zssl's own `transfer_aes128` and `record_aes128` agree to within
# a fraction of a percent — the state machine above the record layer costs
# almost nothing, so comparing rustls's full path against zssl's record
# path does not quietly drop a layer.
ALIASES = {
    ("zssl", "record_aes256"): "transfer_aes256",
    ("zssl", "record_chacha20"): "transfer_chacha20",
}

# Scenarios in the order a reader wants them, with the section headings
# that say what class of thing each block is measuring.
SECTIONS = [
    ("Handshake", ["handshake_full", "handshake_resume"]),
    (
        "Handshake, by flight",
        [
            "phase_client_hello",
            "phase_server_flight",
            "phase_client_finish",
            "phase_server_finish",
        ],
    ),
    (
        "Bulk data (16 KiB record, sealed and opened)",
        ["transfer_aes128", "transfer_aes256", "transfer_chacha20"],
    ),
    (
        "zssl only: the record layer with no state machine over it",
        ["record_aes128"],
    ),
    (
        "Primitives",
        [
            "aead_seal_aes128",
            "aead_seal_aes256",
            "aead_seal_chacha20",
            "aead_key_init",
            "ecdsa_p256_sign",
            "ecdsa_p256_verify",
            "x25519_keygen_agree",
            "x25519_public",
            "x25519_shared",
            "p256_verify_stdcrypto",
        ],
    ),
]


def load(path):
    samples = {}
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            row = json.loads(line)
            name = ALIASES.get((row["impl"], row["name"]), row["name"])
            samples[name] = row
    return samples


def human(row):
    """A duration, or a throughput when the scenario moves bytes."""
    nanoseconds = row["best_ns"]
    if row["bytes_per_op"]:
        gigabytes = row["bytes_per_op"] / nanoseconds
        return f"{nanoseconds / 1000:8.2f} us  {gigabytes:5.2f} GB/s"
    if nanoseconds >= 1000:
        return f"{nanoseconds / 1000:8.2f} us" + " " * 12
    return f"{nanoseconds:8.1f} ns" + " " * 12


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zssl", required=True)
    parser.add_argument("--rustls", required=True)
    arguments = parser.parse_args()

    zssl = load(arguments.zssl)
    rustls = load(arguments.rustls)

    width = 26
    print(f"{'scenario':<{width}}{'zssl':>26}{'rustls':>26}   ratio")
    print("-" * (width + 26 + 26 + 12))

    seen = set()
    for heading, names in SECTIONS:
        print(f"\n{heading}")
        for name in names:
            seen.add(name)
            left, right = zssl.get(name), rustls.get(name)
            if left is None and right is None:
                continue
            left_text = human(left) if left else " " * 26
            right_text = human(right) if right else " " * 26
            if left and right:
                ratio = left["best_ns"] / right["best_ns"]
                verdict = (
                    f"{ratio:5.2f}x slower" if ratio > 1 else f"{1 / ratio:5.2f}x faster"
                )
            else:
                verdict = "one side only"
            print(f"  {name:<{width - 2}}{left_text:>26}{right_text:>26}   {verdict}")

    leftovers = sorted((set(zssl) | set(rustls)) - seen)
    if leftovers:
        print("\nUnclassified (add to SECTIONS in bench/compare.py)")
        for name in leftovers:
            print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
