//! rustls's half of the zssl comparison.
//!
//! Every scenario name here matches one in `bench/zssl_bench.zig`, and the
//! timing harness below is a line-for-line transliteration of that file's:
//! same warmup, same fifteen rounds, same best-and-median reporting, same
//! JSON-lines output. Only the library under the loop differs.
//!
//! Both peers live in this process and talk through a `Vec<u8>`; nothing
//! measured touches a socket or a thread.

use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::aws_lc_rs as rustls_aws_lc;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, SignatureScheme};

// The same throwaway self-signed fixtures the Zig harness loads, embedded
// from the tree rather than copied.
const CERT_PEM: &[u8] = include_bytes!("../../../src/testdata/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("../../../src/testdata/key.pem");

const SERVER_NAME: &str = "spike.zoxy.test";
const ALPN: &[u8] = b"http/1.1";

/// One full 16 KiB record's worth of plaintext, matching `chunk_bytes` in
/// the Zig harness.
const CHUNK_BYTES: usize = 16384;

// ---------------------------------------------------------------------
// Timing — mirrors `measure` in bench/zssl_bench.zig
// ---------------------------------------------------------------------

const ROUNDS: usize = 15;

fn report(name: &str, unit: &str, best_ns: f64, median_ns: f64, bytes_per_op: u64, iterations: usize) {
    println!(
        "{{\"impl\":\"rustls\",\"name\":\"{name}\",\"unit\":\"{unit}\",\
          \"best_ns\":{best_ns:.3},\"median_ns\":{median_ns:.3},\
          \"bytes_per_op\":{bytes_per_op},\"iterations\":{iterations}}}"
    );
}

/// Run `body` for `ROUNDS` rounds of `iterations` each and report. The
/// value `body` returns is passed through `black_box`, so a scenario
/// whose result nobody reads is not optimised into nothing.
fn measure<F>(name: &str, unit: &str, bytes_per_op: u64, iterations: usize, mut body: F)
where
    F: FnMut(usize) -> u64,
{
    assert!(iterations >= 1);
    // Warm up: the first touch pays for page faults and a cold predictor,
    // neither of which the steady state pays again.
    std::hint::black_box(body(std::cmp::max(1, iterations / 4)));

    let mut per_round = [0.0f64; ROUNDS];
    for slot in per_round.iter_mut() {
        let started = Instant::now();
        let sink = body(iterations);
        let elapsed = started.elapsed();
        std::hint::black_box(sink);
        *slot = elapsed.as_nanos() as f64 / iterations as f64;
    }
    per_round.sort_by(|a, b| a.partial_cmp(b).unwrap());
    report(name, unit, per_round[0], per_round[ROUNDS / 2], bytes_per_op, iterations);
}

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

/// The exact counterpart of zssl's `CertificatePolicy.leaf_signature`:
/// the CertificateVerify signature is checked against the leaf's own
/// public key, and chain building plus name matching are left to the
/// embedder. Handing rustls its full webpki verifier here would compare
/// a handshake that validates a chain against one that does not.
#[derive(Debug)]
struct LeafSignatureOnly {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for LeafSignatureOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn certified_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let certs = rustls_pemfile::certs(&mut &CERT_PEM[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("cert.pem");
    let key = rustls_pemfile::private_key(&mut &KEY_PEM[..])
        .expect("key.pem")
        .expect("key.pem holds no private key");
    (certs, key)
}

/// A provider narrowed to one suite and to X25519, so the negotiated
/// parameters are the ones the Zig harness measures rather than whatever
/// the default preference order happens to pick.
fn provider_for(suite: rustls::SupportedCipherSuite) -> Arc<CryptoProvider> {
    let mut provider = rustls_aws_lc::default_provider();
    provider.cipher_suites = vec![suite];
    provider.kx_groups = vec![rustls_aws_lc::kx_group::X25519];
    Arc::new(provider)
}

struct Configs {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
}

fn configs(suite: rustls::SupportedCipherSuite, tickets: bool) -> Configs {
    let provider = provider_for(suite);
    let (certs, key) = certified_key();

    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server.alpn_protocols = vec![ALPN.to_vec()];
    if tickets {
        server.ticketer = rustls_aws_lc::Ticketer::new().expect("ticketer");
    } else {
        server.send_tls13_tickets = 0;
    }

    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(LeafSignatureOnly { provider }))
        .with_no_client_auth();
    client.alpn_protocols = vec![ALPN.to_vec()];
    client.resumption = if tickets {
        Resumption::in_memory_sessions(64)
    } else {
        Resumption::disabled()
    };

    Configs {
        client: Arc::new(client),
        server: Arc::new(server),
    }
}

// ---------------------------------------------------------------------
// Driving a pair in memory
// ---------------------------------------------------------------------

/// Move whatever one peer wants to write into the other, reusing one
/// allocation. This is rustls's own test-harness shape: `write_tls` into a
/// buffer, `read_tls` back out of it.
macro_rules! transfer {
    ($from:expr, $to:expr, $wire:expr) => {{
        $wire.clear();
        while $from.wants_write() {
            $from.write_tls(&mut $wire).expect("write_tls");
        }
        let mut cursor: &[u8] = &$wire[..];
        while !cursor.is_empty() {
            $to.read_tls(&mut cursor).expect("read_tls");
            $to.process_new_packets().expect("process_new_packets");
        }
    }};
}

fn handshake(client: &mut ClientConnection, server: &mut ServerConnection, mut wire: &mut Vec<u8>) {
    while client.is_handshaking() || server.is_handshaking() {
        transfer!(client, server, wire);
        transfer!(server, client, wire);
    }
    // Drain the post-handshake flight (NewSessionTicket) so a resumption
    // run has a ticket to find in the store.
    transfer!(server, client, wire);
}

/// The four flights a full handshake is made of, timed separately inside
/// one iteration — the counterpart of `handshakePhases` in the Zig
/// harness, split at the same four points.
fn handshake_phases(configs: &Configs, wire: &mut Vec<u8>, totals: &mut [u128; 4]) {
    // `ClientConnection::new` is inside phase one, not before it: rustls
    // builds the ClientHello — key share and all — in the constructor,
    // while zssl builds it in `client.start()`. Timing from after the
    // constructor would put rustls's X25519 keygen in nobody's phase and
    // report a first flight of forty nanoseconds.
    let t0 = Instant::now();
    let (mut client, mut server) = new_pair(configs);
    wire.clear();
    while client.wants_write() {
        client.write_tls(wire).expect("write_tls");
    }
    let t1 = Instant::now();

    {
        let mut cursor: &[u8] = &wire[..];
        while !cursor.is_empty() {
            server.read_tls(&mut cursor).expect("read_tls");
            server.process_new_packets().expect("process_new_packets");
        }
        wire.clear();
        while server.wants_write() {
            server.write_tls(wire).expect("write_tls");
        }
    }
    let t2 = Instant::now();

    {
        let mut cursor: &[u8] = &wire[..];
        while !cursor.is_empty() {
            client.read_tls(&mut cursor).expect("read_tls");
            client.process_new_packets().expect("process_new_packets");
        }
        wire.clear();
        while client.wants_write() {
            client.write_tls(wire).expect("write_tls");
        }
    }
    let t3 = Instant::now();

    {
        let mut cursor: &[u8] = &wire[..];
        while !cursor.is_empty() {
            server.read_tls(&mut cursor).expect("read_tls");
            server.process_new_packets().expect("process_new_packets");
        }
    }
    let t4 = Instant::now();

    assert!(!client.is_handshaking() && !server.is_handshaking());
    totals[0] += t1.duration_since(t0).as_nanos();
    totals[1] += t2.duration_since(t1).as_nanos();
    totals[2] += t3.duration_since(t2).as_nanos();
    totals[3] += t4.duration_since(t3).as_nanos();
}

/// The phase breakdown under the same rounds-and-median discipline as
/// `measure`, reporting four numbers per round instead of one.
fn measure_phases(configs: &Configs, wire: &mut Vec<u8>, iterations: usize) {
    let names = [
        "phase_client_hello",
        "phase_server_flight",
        "phase_client_finish",
        "phase_server_finish",
    ];
    let mut scratch = [0u128; 4];
    for _ in 0..std::cmp::max(1, iterations / 4) {
        handshake_phases(configs, wire, &mut scratch);
    }

    let mut per_round = [[0.0f64; ROUNDS]; 4];
    for round in 0..ROUNDS {
        let mut totals = [0u128; 4];
        for _ in 0..iterations {
            handshake_phases(configs, wire, &mut totals);
        }
        for phase in 0..4 {
            per_round[phase][round] = totals[phase] as f64 / iterations as f64;
        }
    }
    for (phase, name) in names.iter().enumerate() {
        let mut sorted = per_round[phase];
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        report(name, "flight", sorted[0], sorted[ROUNDS / 2], 0, iterations);
    }
}

fn new_pair(configs: &Configs) -> (ClientConnection, ServerConnection) {
    let name = ServerName::try_from(SERVER_NAME).expect("server name");
    let client = ClientConnection::new(configs.client.clone(), name).expect("client");
    let server = ServerConnection::new(configs.server.clone()).expect("server");
    (client, server)
}

// ---------------------------------------------------------------------

fn main() {
    let suites = [
        ("aes128", rustls_aws_lc::cipher_suite::TLS13_AES_128_GCM_SHA256),
        ("aes256", rustls_aws_lc::cipher_suite::TLS13_AES_256_GCM_SHA384),
        (
            "chacha20",
            rustls_aws_lc::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
    ];

    let mut wire: Vec<u8> = Vec::with_capacity(64 * 1024);

    // ---- handshake_full -------------------------------------------
    let full = configs(suites[0].1, false);
    measure("handshake_full", "handshake", 0, 200, |iterations| {
        let mut accumulator = 0u64;
        for _ in 0..iterations {
            let (mut client, mut server) = new_pair(&full);
            handshake(&mut client, &mut server, &mut wire);
            assert!(!client.is_handshaking() && !server.is_handshaking());
            accumulator = accumulator.wrapping_add(1);
        }
        accumulator
    });

    measure_phases(&full, &mut wire, 200);

    // ---- handshake_resume -----------------------------------------
    // One priming handshake fills the client's session store; from then
    // on every handshake in the loop is a PSK handshake, which the assert
    // below refuses to let silently stop being true.
    let resumed = configs(suites[0].1, true);
    {
        let (mut client, mut server) = new_pair(&resumed);
        handshake(&mut client, &mut server, &mut wire);
    }
    measure("handshake_resume", "handshake", 0, 200, |iterations| {
        let mut accumulator = 0u64;
        for _ in 0..iterations {
            let (mut client, mut server) = new_pair(&resumed);
            handshake(&mut client, &mut server, &mut wire);
            assert_eq!(
                server.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed),
                "expected a resumed handshake, got a full one"
            );
            accumulator = accumulator.wrapping_add(1);
        }
        accumulator
    });

    // ---- transfer_* ------------------------------------------------
    // Server seals one 16 KiB record, client opens it. The same work the
    // Zig harness calls `transfer_aes128` and `record_*`: one seal and one
    // open per iteration, over the library's own public API.
    let plaintext: Vec<u8> = (0..CHUNK_BYTES).map(|index| index as u8).collect();
    let mut received = vec![0u8; CHUNK_BYTES];
    for (label, suite) in suites {
        let pair_configs = configs(suite, false);
        let (mut client, mut server) = new_pair(&pair_configs);
        handshake(&mut client, &mut server, &mut wire);
        measure(
            &format!("transfer_{label}"),
            "byte",
            CHUNK_BYTES as u64,
            4000,
            |iterations| {
                let mut accumulator = 0u64;
                for _ in 0..iterations {
                    server.writer().write_all(&plaintext).expect("writer");
                    wire.clear();
                    while server.wants_write() {
                        server.write_tls(&mut wire).expect("write_tls");
                    }
                    let mut cursor: &[u8] = &wire[..];
                    while !cursor.is_empty() {
                        client.read_tls(&mut cursor).expect("read_tls");
                        client.process_new_packets().expect("process_new_packets");
                    }
                    let read = std::io::Read::read(&mut client.reader(), &mut received)
                        .expect("reader");
                    accumulator = accumulator.wrapping_add(read as u64);
                }
                accumulator
            },
        );
    }

    // ---- aead_seal_* -----------------------------------------------
    // The primitive floor: one 16 KiB seal, no record layer above it.
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
    let aeads = [
        ("aes128", &AES_128_GCM),
        ("aes256", &AES_256_GCM),
        ("chacha20", &CHACHA20_POLY1305),
    ];
    for (label, algorithm) in aeads {
        let key_bytes = vec![0xabu8; algorithm.key_len()];
        let key = LessSafeKey::new(UnboundKey::new(algorithm, &key_bytes).expect("key"));
        let aad_bytes = [0x17u8, 0x03, 0x03, 0x40, 0x11];
        let mut buffer = vec![0u8; CHUNK_BYTES];
        measure(
            &format!("aead_seal_{label}"),
            "byte",
            CHUNK_BYTES as u64,
            8000,
            |iterations| {
                let mut accumulator = 0u64;
                for _ in 0..iterations {
                    buffer.copy_from_slice(&plaintext);
                    let tag = key
                        .seal_in_place_separate_tag(
                            Nonce::assume_unique_for_key([0x11u8; 12]),
                            Aad::from(&aad_bytes),
                            &mut buffer,
                        )
                        .expect("seal");
                    accumulator = accumulator.wrapping_add(tag.as_ref()[0] as u64);
                }
                accumulator
            },
        );
    }

    // ---- aead_key_init ---------------------------------------------
    // Standing up one traffic key. A TLS 1.3 handshake does this eight
    // times across both peers, so a per-key setup cost that looks trivial
    // in isolation is multiplied by eight in the handshake number above.
    {
        let key_bytes = vec![0xabu8; AES_128_GCM.key_len()];
        measure("aead_key_init", "key", 0, 4000, |iterations| {
            let mut accumulator = 0u64;
            for _ in 0..iterations {
                let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).expect("key"));
                accumulator =
                    accumulator.wrapping_add(key.algorithm().key_len() as u64);
            }
            accumulator
        });
    }

    // ---- asymmetric primitives -------------------------------------
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    };
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("pkcs8");
    let keypair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).expect("keypair");
    let content = [0x20u8; 130];
    measure("ecdsa_p256_sign", "signature", 0, 2000, |iterations| {
        let mut accumulator = 0u64;
        for _ in 0..iterations {
            let signature = keypair.sign(&rng, &content).expect("sign");
            accumulator = accumulator.wrapping_add(signature.as_ref().len() as u64);
        }
        accumulator
    });

    let signature = keypair.sign(&rng, &content).expect("sign");
    let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, keypair.public_key().as_ref());
    measure("ecdsa_p256_verify", "verification", 0, 2000, |iterations| {
        for _ in 0..iterations {
            public.verify(&content, signature.as_ref()).expect("verify");
        }
        signature.as_ref().len() as u64
    });

    // One keygen (a scalar mult against the base point) plus one agree
    // (a scalar mult against the peer's point) per iteration — the same
    // two operations `x25519Body` runs through `x25519Public` and
    // `x25519Shared` on the Zig side.
    use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey as KxPublicKey, X25519};
    measure("x25519_keygen_agree", "exchange", 0, 2000, |iterations| {
        let mut accumulator = 0u64;
        for _ in 0..iterations {
            let private = PrivateKey::generate(&X25519).expect("keygen");
            let public = private.compute_public_key().expect("public");
            let peer = KxPublicKey::new(&X25519, public.as_ref());
            let byte = agree(&private, &peer, (), |shared| Ok(shared[0])).expect("agree");
            accumulator = accumulator.wrapping_add(byte as u64);
        }
        accumulator
    });
}
