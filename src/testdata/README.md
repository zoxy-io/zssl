# TLS test fixtures — NOT secrets

Throwaway self-signed material, generated with the openssl CLI solely
for the tests and gates in this tree. The private keys are committed
**on purpose**: they sign nothing but in-memory test handshakes and
loopback connections, are trusted by nothing, and must never be reused
anywhere. CLAUDE.md says the same thing in one line, and this file is
where the recipes live so a regenerated fixture matches the one it
replaces.

`cert.pem` / `key.pem` are shared with zoxy's `src/tls/testdata/` — the
same pair, kept in step by hand. The rest are zssl's own.

| File | What it is | Who needs it |
| --- | --- | --- |
| `cert.pem`, `key.pem` | P-256 leaf, `ecdsa-with-SHA256` | most of the suite; interop leg 1; the tlsfuzzer gate's ECDSA leaf |
| `p384-cert.pem`, `p384-key.pem` | P-384 leaf, `ecdsa-with-SHA384` | interop leg 2, and the `client_server_test` that exercises `ecdsa_secp384r1_sha384` |
| `rsa2048-cert.pem`, `rsa2048-key.pem` | RSA-2048 leaf | the RSA signing path; the tlsfuzzer gate's RSA leaf |
| `rsa1024-key.pem` | RSA-1024 key, no certificate | proving `rsa_bits_min` is a load-time refusal |
| `rsa512-leaf.der` | RSA-512 leaf, DER | proving the client refuses a modulus below the floor |

Subject and SAN are `spike.zoxy.test` throughout, because the interop
gate passes `-servername spike.zoxy.test` and openssl's X.509 verifies
the name.

## Regenerating

```sh
# P-256 — keep zoxy's copy in step.
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -subj "/CN=spike.zoxy.test" \
  -addext "subjectAltName=DNS:spike.zoxy.test" -days 3650 -out cert.pem

# P-384. -sha384 is not decoration: the self-signature should be the
# digest the curve names, so the fixture does not quietly depend on
# openssl's default.
openssl ecparam -name secp384r1 -genkey -noout -out p384-key.pem
openssl req -new -x509 -key p384-key.pem -subj "/CN=spike.zoxy.test" \
  -addext "subjectAltName=DNS:spike.zoxy.test" -days 3650 -sha384 \
  -out p384-cert.pem

# RSA-2048.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out rsa2048-key.pem
openssl req -new -x509 -key rsa2048-key.pem -subj "/CN=spike.zoxy.test" \
  -addext "subjectAltName=DNS:spike.zoxy.test" -days 3650 \
  -out rsa2048-cert.pem
```

The two undersized RSA fixtures exist to be refused and have no reason
to be regenerated; if they ever are, they must stay below
`backend.rsa_bits_min` or the tests they serve stop testing anything.

## Why there is no P-521 or RSA-PSS-key leaf

Neither is a fixture question. `ecdsa_secp521r1_sha512` and
`rsa_pss_pss_*` are not in `backend.SignatureScheme` at all, and
DESIGN.md §1 puts P-256/P-384 and RSA-PSS-`rsae` in the signing policy —
so adding either leaf would be a policy change first and a `.pem`
second. `docs/TLSFUZZER.md` records the two scripts that want them.
