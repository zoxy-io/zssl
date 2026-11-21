#!/usr/bin/env python3
"""Extract RFC 9001's packet-protection vectors into a Zig source file.

Lifts Appendix A's worked examples (A.1's Initial keys, A.2 and A.3's
protected Initial packets, A.4's Retry, A.5's ChaCha20-Poly1305 short
header packet) and the two constants the appendix leans on from the
body — section 5.2's Initial salt and section 5.8's Retry key and nonce —
as fixed-size Zig arrays.

Every value is found by an anchor *inside its own section*, and every
one is checked against the octet count the algorithm or the RFC's prose
fixes, so an anchor that drifts onto a neighbouring block fails here
rather than emitting a plausible wrong fixture. The tests then derive
each value independently and compare, which is the check a length
cannot make.

Usage: python3 scripts/extract_rfc9001.py rfc9001.txt src/rfc9001_vectors.zig
"""
import re
import sys

SRC = sys.argv[1]
OUT = sys.argv[2]

with open(SRC) as f:
    LINES = [line.rstrip("\n") for line in f]

HEX_RUN = re.compile(r"^(?:0x)?([0-9a-f]+(?: [0-9a-f]+)*)\.?$")


def section(start, end):
    """The lines strictly between the heading `start` and the next `end`."""
    first = next(i for i, line in enumerate(LINES) if line == start)
    last = next(i for i, line in enumerate(LINES) if i > first and line.startswith(end))
    return LINES[first + 1:last]


def hex_of(text):
    """The hex run in `text` after any `name =`, `name:` or `equal to`
    prefix, or None. Section 5.8 states its constants in prose."""
    text = text.strip()
    for separator in ("=", ":", "equal to"):
        if separator in text:
            text = text.split(separator, 1)[1].strip()
    match = HEX_RUN.match(text)
    if not match:
        return None
    return bytes.fromhex(match.group(1).replace(" ", ""))


def labelled(lines, anchor, count):
    """A value introduced by the first line containing `anchor`.

    The value starts on the anchor line if it carries hex, otherwise on
    the first `= <hex>` line after it, and runs over continuation lines
    of bare hex until anything else.
    """
    index = next(i for i, line in enumerate(lines) if anchor in line)
    data = hex_of(lines[index])
    cursor = index + 1
    while data is None:
        data = hex_of(lines[cursor])
        cursor += 1
    data = bytearray(data)
    while cursor < len(lines):
        more = hex_of(lines[cursor]) if "=" not in lines[cursor] else None
        if more is None:
            break
        data.extend(more)
        cursor += 1
    return checked(anchor, bytes(data), count)


def block(lines, anchor, count):
    """A bare indented hex block following the prose line `anchor`."""
    index = next(i for i, line in enumerate(lines) if anchor in line)
    cursor = index + 1
    while lines[cursor].strip() == "":
        cursor += 1
    data = bytearray()
    while cursor < len(lines) and lines[cursor].strip() != "":
        piece = hex_of(lines[cursor])
        assert piece is not None, f"non-hex line inside block after {anchor!r}"
        data.extend(piece)
        cursor += 1
    return checked(anchor, bytes(data), count)


def checked(anchor, data, count):
    if len(data) != count:
        sys.exit(f"{anchor!r}: expected {count} octets, found {len(data)}")
    return data


def number(lines, pattern):
    for line in lines:
        match = re.search(pattern, line)
        if match:
            return int(match.group(1))
    sys.exit(f"no match for {pattern!r}")


salt_section = section("5.2.  Initial Secrets", "5.3.  ")
retry_section = section("5.8.  Retry Packet Integrity", "6.  ")
a1 = section("A.1.  Keys", "A.2.  ")
a2 = section("A.2.  Client Initial", "A.3.  ")
a3 = section("A.3.  Server Initial", "A.4.  ")
a4 = section("A.4.  Retry", "A.5.  ")
a5 = section("A.5.  ChaCha20-Poly1305 Short Header Packet", "Appendix B.")

# The client's two A.1 derivations sit above the server's, so anchors
# naming the secret they expand are what tell the two sets apart.
VECTORS = [
    ("initial_salt", "section 5.2", labelled(salt_section, "initial_salt = 0x", 20)),
    ("retry_key", "section 5.8", labelled(retry_section, "The secret key, K, is 128 bits", 16)),
    ("retry_nonce", "section 5.8", labelled(retry_section, "The nonce, N, is 96 bits", 12)),
    ("initial_secret", "A.1", labelled(a1, "initial_secret = HKDF-Extract", 32)),
    ("client_initial_secret", "A.1", labelled(a1, "client_initial_secret", 32)),
    ("client_key", "A.1", labelled(a1, "key = HKDF-Expand-Label(client_initial_secret", 16)),
    ("client_iv", "A.1", labelled(a1, "iv  = HKDF-Expand-Label(client_initial_secret", 12)),
    ("client_hp", "A.1", labelled(a1, "hp  = HKDF-Expand-Label(client_initial_secret", 16)),
    ("server_initial_secret", "A.1", labelled(a1, "server_initial_secret", 32)),
    ("server_key", "A.1", labelled(a1, "key = HKDF-Expand-Label(server_initial_secret", 16)),
    ("server_iv", "A.1", labelled(a1, "iv  = HKDF-Expand-Label(server_initial_secret", 12)),
    ("server_hp", "A.1", labelled(a1, "hp  = HKDF-Expand-Label(server_initial_secret", 16)),
    # A.2: 0x06 type, 0x00 offset, a 0x40f1-octet body behind its
    # two-byte length — 245 octets of CRYPTO frame before the padding.
    ("client_crypto_frame", "A.2", block(a2, "frames to make a 1162-byte payload:", 245)),
    ("client_header", "A.2", block(a2, "packet number of 2:", 22)),
    ("client_sample", "A.2", labelled(a2, "sample = ", 16)),
    ("client_mask", "A.2", labelled(a2, "mask = AES-ECB(hp, sample)", 5)),
    ("client_protected_header", "A.2", labelled(a2, "header = c0", 22)),
    ("client_packet", "A.2", block(a2, "The resulting protected packet is:", 1200)),
    # A.3's header carries a Length of 0x75: two packet-number octets,
    # the payload, and a sixteen-octet tag — so 99 octets of payload.
    ("server_payload", "A.3", block(a3, "and no PADDING frames:", 99)),
    ("server_header", "A.3", block(a3, "packet number of 1:", 20)),
    ("server_sample", "A.3", labelled(a3, "sample = ", 16)),
    ("server_mask", "A.3", labelled(a3, "mask   = ", 5)),
    ("server_protected_header", "A.3", labelled(a3, "   header = ", 20)),
    ("server_packet", "A.3", block(a3, "The final protected packet is then:", 135)),
    ("retry_packet", "A.4", block(a4, "not included in the final Retry packet:", 36)),
    ("chacha_secret", "A.5", labelled(a5, "   secret", 32)),
    ("chacha_key", "A.5", labelled(a5, 'key = HKDF-Expand-Label(secret, "quic key"', 32)),
    ("chacha_iv", "A.5", labelled(a5, 'iv  = HKDF-Expand-Label(secret, "quic iv"', 12)),
    ("chacha_hp", "A.5", labelled(a5, 'hp  = HKDF-Expand-Label(secret, "quic hp"', 32)),
    ("chacha_ku", "A.5", labelled(a5, 'ku  = HKDF-Expand-Label(secret, "quic ku"', 32)),
    ("chacha_nonce", "A.5", labelled(a5, "nonce              =", 12)),
    ("chacha_header", "A.5", labelled(a5, "unprotected header =", 4)),
    ("chacha_plaintext", "A.5", labelled(a5, "payload plaintext  =", 1)),
    ("chacha_ciphertext", "A.5", labelled(a5, "payload ciphertext =", 17)),
    ("chacha_sample", "A.5", labelled(a5, "sample = ", 16)),
    ("chacha_mask", "A.5", labelled(a5, "mask   = ", 5)),
    ("chacha_protected_header", "A.5", labelled(a5, "   header = ", 4)),
    ("chacha_packet", "A.5", labelled(a5, "packet = ", 21)),
]

NUMBERS = [
    ("client_packet_number", "A.2", number(a2, r"packet number of (\d+):")),
    ("server_packet_number", "A.3", number(a3, r"packet number of (\d+):")),
    ("chacha_packet_number", "A.5", number(a5, r"pn\s+= (\d+) \(decimal\)")),
]

with open(OUT, "w") as out:
    out.write("//! RFC 9001 packet-protection vectors: Appendix A's worked packets,\n")
    out.write("//! section 5.2's Initial salt and section 5.8's Retry key and nonce.\n")
    out.write("//!\n")
    out.write("//! Generated by scripts/extract_rfc9001.py from the RFC text — do not\n")
    out.write("//! edit by hand; regenerate instead.\n")
    for name, where, data in VECTORS:
        body = ", ".join(f"0x{b:02x}" for b in data)
        # zig fmt pads a list's braces with spaces, except around a
        # single element; emitting its shape keeps the format gate green.
        padded = body if len(data) == 1 else f" {body} "
        out.write(f"\n// RFC 9001 {where} — {name} ({len(data)} octets).\n")
        out.write(f"pub const {name} = [{len(data)}]u8{{{padded}}};\n")
    for name, where, value in NUMBERS:
        out.write(f"\n// RFC 9001 {where} — {name}.\n")
        out.write(f"pub const {name}: u64 = {value};\n")
