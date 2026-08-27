#!/usr/bin/env python3
"""Extract named test vectors from RFC 8448 into a Zig source file.

Parses the `{client}/{server}` trace blocks of rfc8448.txt and emits the
subset of items zssl's tests assert against, as fixed-size Zig arrays.
Selection is by (block start line, item name) so repeated generic item
names ("expanded", "key", "payload") stay unambiguous.
"""
import re
import sys

SRC = sys.argv[1]
OUT = sys.argv[2]

page_noise = re.compile(r"^(Thomson\s+Informational\s+\[Page \d+\]|RFC 8448\s+TLS 1\.3 Traces\s+January 2019|\f.*)$")
block_re = re.compile(r"^   \{(client|server)\}  (.+?):?\s*$")
item_re = re.compile(r"^      ([A-Za-z0-9_ ]+?) \((\d+) octets\):\s+((?:[0-9a-f]{2}\s*)+)$")
cont_re = re.compile(r"^         ((?:[0-9a-f]{2}\s*)+)$")

blocks = []  # (line_no, who, title, items: {name: bytes})
cur = None
cur_item = None

with open(SRC) as f:
    for line_no, raw in enumerate(f, 1):
        line = raw.rstrip("\n")
        if page_noise.match(line):
            continue
        m = block_re.match(line)
        if m:
            cur = (line_no, m.group(1), m.group(2), {})
            blocks.append(cur)
            cur_item = None
            continue
        if cur is None:
            continue
        m = item_re.match(line)
        if m:
            name, count, hexes = m.group(1), int(m.group(2)), m.group(3)
            data = bytearray(bytes.fromhex(hexes.replace(" ", "")))
            cur[3][name] = (count, data)
            cur_item = name
            continue
        m = cont_re.match(line)
        if m and cur_item is not None:
            cur[3][cur_item][1].extend(bytes.fromhex(m.group(1).replace(" ", "")))
            continue
        if line.strip() == "":
            continue
        cur_item = None  # prose or a non-hex item ends continuation

by_line = {b[0]: b for b in blocks}

# (zig_name, block_line, item_name)
WANT = [
    ("client_x25519_private", 160, "private key"),
    ("client_x25519_public", 160, "public key"),
    ("client_hello", 175, "ClientHello"),
    ("early_secret", 212, "secret"),
    ("server_x25519_private", 231, "private key"),
    ("server_x25519_public", 231, "public key"),
    ("server_hello", 239, "ServerHello"),
    ("derived_for_handshake", 247, "expanded"),
    ("ecdhe_shared_secret", 262, "IKM"),
    ("handshake_secret", 262, "secret"),
    ("client_hs_traffic_secret", 273, "expanded"),
    ("server_hs_traffic_secret", 297, "expanded"),
    ("derived_for_master", 312, "expanded"),
    ("master_secret", 327, "secret"),
    ("server_hs_key", 360, "key expanded"),
    ("server_hs_iv", 360, "iv expanded"),
    ("encrypted_extensions", 374, "EncryptedExtensions"),
    ("certificate", 380, "Certificate"),
    ("certificate_verify", 413, "CertificateVerify"),
    ("server_finished_key", 423, "expanded"),
    ("server_finished", 439, "Finished"),
    ("server_flight_plaintext", 455, "payload"),
    ("server_flight_record", 455, "complete record"),
    ("client_ap_traffic_secret", 532, "expanded"),
    ("server_ap_traffic_secret", 547, "expanded"),
    ("exporter_master_secret", 570, "expanded"),
    ("server_ap_key", 585, "key expanded"),
    ("server_ap_iv", 585, "iv expanded"),
    ("client_hs_key", 599, "key expanded"),
    ("client_hs_iv", 599, "iv expanded"),
    ("client_finished_key", 666, "expanded"),
    ("client_finished", 690, "Finished"),
    ("client_finished_plaintext", 696, "payload"),
    ("client_finished_record", 696, "complete record"),
    ("client_ap_key", 706, "key expanded"),
    ("client_ap_iv", 706, "iv expanded"),
    ("resumption_master_secret", 720, "expanded"),
    ("resumption_psk", 749, "expanded"),
    ("new_session_ticket", 762, "NewSessionTicket"),
    ("ticket_plaintext", 776, "payload"),
    ("ticket_record", 776, "complete record"),
    ("client_app_plaintext", 814, "payload"),
    ("client_app_record", 814, "complete record"),
    ("server_app_plaintext", 825, "payload"),
    ("server_app_record", 825, "complete record"),
    ("client_alert_plaintext", 836, "payload"),
    ("client_alert_record", 836, "complete record"),
    # §4 "Resumed 0-RTT Handshake" — the PSK/binder side of resumption.
    # zssl does not implement 0-RTT, so the early-data vectors stay out;
    # what these pin is the binder chain, the PSK-mixed key ladder, and
    # the pre_shared_key ServerHello.
    ("resumed_client_x25519_private", 866, "private key"),
    ("resumed_client_x25519_public", 866, "public key"),
    ("resumed_psk", 874, "IKM"),
    ("resumed_early_secret", 874, "secret"),
    # Block 884's "ClientHello" is the message *without* its binders
    # section (the trace prints it pre-binder); the full 512-byte message
    # is the send-record payload.
    ("resumed_client_hello", 970, "payload"),
    ("resumed_client_hello_truncated", 884, "ClientHello"),
    ("resumed_binder_hash", 919, "binder hash"),
    ("resumed_binder_key", 919, "PRK"),
    ("resumed_binder_finished_key", 919, "expanded"),
    ("resumed_binder_value", 919, "finished"),
    ("resumed_server_x25519_private", 1096, "private key"),
    ("resumed_server_x25519_public", 1096, "public key"),
    ("resumed_server_hello", 1108, "ServerHello"),
    ("resumed_ecdhe_shared", 1142, "IKM"),
    ("resumed_handshake_secret", 1142, "secret"),
    ("resumed_client_hs_traffic_secret", 1153, "expanded"),
    ("resumed_server_hs_traffic_secret", 1168, "expanded"),
    ("resumed_master_secret", 1205, "secret"),
]

lines = [
    "//! RFC 8448 §3 \"Simple 1-RTT Handshake\" trace vectors.",
    "//!",
    "//! Generated by scripts/extract_rfc8448.py from the RFC text — do not",
    "//! edit by hand; regenerate instead. The suite in this trace is",
    "//! TLS_AES_128_GCM_SHA256 with x25519 key exchange.",
    "",
]
errors = []
for zig_name, block_line, item in WANT:
    b = by_line.get(block_line)
    if b is None:
        errors.append(f"no block at line {block_line} for {zig_name}")
        continue
    got = b[3].get(item)
    if got is None:
        errors.append(f"block {block_line} ({b[2]!r}) has no item {item!r}; has {list(b[3])}")
        continue
    count, data = got
    if count != len(data):
        errors.append(f"{zig_name}: declared {count} octets, parsed {len(data)}")
        continue
    hexes = ", ".join(f"0x{x:02x}" for x in data)
    lines.append(f"// {b[2]} — {item} ({count} octets).")
    lines.append(f"pub const {zig_name} = [{count}]u8{{ {hexes} }};")
    lines.append("")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)

with open(OUT, "w") as f:
    f.write("\n".join(lines))
print(f"wrote {OUT}: {len(WANT)} vectors")
