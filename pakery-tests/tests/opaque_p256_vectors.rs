//! OPAQUE P-256 integration tests.
//!
//! No RFC 9807 test vectors exist for P-256, so these are round-trip tests.
#![cfg(feature = "p256")]

use pakery_core::crypto::dh::DhGroup;
use pakery_core::crypto::IdentityKsf;
use pakery_crypto::{HkdfSha256, HmacSha256, P256Dh, P256Oprf, Sha256Hash};
use pakery_opaque::{
    ClientLogin, ClientRegistration, OpaqueCiphersuite, OpaqueError, ServerLogin,
    ServerRegistration, ServerSetup,
};

/// OPAQUE ciphersuite: P-256 + SHA-256 + IdentityKSF.
struct OpaqueP256Sha256;

impl OpaqueCiphersuite for OpaqueP256Sha256 {
    type Hash = Sha256Hash;
    type Kdf = HkdfSha256;
    type Mac = HmacSha256;
    type Dh = P256Dh;
    type Oprf = P256Oprf;
    type Ksf = IdentityKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 33;
    const NOK: usize = 32;
    const NM: usize = 32;
    const NH: usize = 32;
    const NPK: usize = 33;
    const NSK: usize = 32;
    const NX: usize = 32;
}

// --- P256Dh basic operations ---

#[test]
fn p256_dh_derive_keypair() {
    let seed = [0x42u8; 32];
    let (sk, pk) = P256Dh::derive_keypair(&seed).unwrap();
    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 33); // compressed SEC1

    // Deterministic: same seed produces same keypair.
    let (sk2, pk2) = P256Dh::derive_keypair(&seed).unwrap();
    assert_eq!(sk, sk2);
    assert_eq!(pk, pk2);
}

#[test]
fn p256_dh_public_key_from_private() {
    let seed = [0xaa; 32];
    let (sk, pk) = P256Dh::derive_keypair(&seed).unwrap();
    let pk2 = P256Dh::public_key_from_private(&sk).unwrap();
    assert_eq!(pk, pk2);
}

#[test]
fn p256_dh_consistency() {
    let mut rng = rand_core::OsRng;
    let (sk_a, pk_a) = P256Dh::generate_keypair(&mut rng).unwrap();
    let (sk_b, pk_b) = P256Dh::generate_keypair(&mut rng).unwrap();

    let shared_ab = P256Dh::diffie_hellman(&sk_a, &pk_b).unwrap();
    let shared_ba = P256Dh::diffie_hellman(&sk_b, &pk_a).unwrap();
    assert_eq!(shared_ab, shared_ba);
}

#[test]
fn p256_dh_rejects_invalid_inputs() {
    let mut rng = rand_core::OsRng;
    let (sk, _pk) = P256Dh::generate_keypair(&mut rng).unwrap();

    // Invalid public key length.
    assert!(P256Dh::diffie_hellman(&sk, &[0x02; 16]).is_err());

    // Invalid scalar length.
    assert!(P256Dh::diffie_hellman(&[0u8; 16], &[0x02; 33]).is_err());

    // Invalid public key (not on curve).
    let mut bad_pk = [0xffu8; 33];
    bad_pk[0] = 0x02;
    assert!(P256Dh::diffie_hellman(&sk, &bad_pk).is_err());
}

// --- Registration round-trip ---

#[test]
fn registration_roundtrip() {
    let mut rng = rand_core::OsRng;
    let password = b"hunter2";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();

    let (record, _export_key) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    // Record should have non-empty fields.
    assert!(!record.client_public_key.is_empty());
    assert!(!record.masking_key.is_empty());
    assert!(!record.envelope.nonce.is_empty());
    assert!(!record.envelope.auth_tag.is_empty());
}

// --- Full login round-trip ---

#[test]
fn login_roundtrip() {
    let mut rng = rand_core::OsRng;
    let password = b"correct horse battery staple";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    // Registration
    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, export_key_reg) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    // Login
    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user1",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let (ke3, client_session_key, export_key_login) = client_state
        .finish(&ke2, b"test-context", b"", b"")
        .unwrap();

    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_eq!(client_session_key, server_session_key);
    assert_eq!(export_key_reg, export_key_login);
}

// --- Wrong password rejection ---

#[test]
fn wrong_password_rejected() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password-A", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password-B", &mut rng).unwrap();

    let (ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(matches!(result, Err(OpaqueError::EnvelopeRecoveryError)));
}

// --- Tampering detection: KE2 server MAC ---

#[test]
fn tampered_server_mac_detected() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();

    let (mut ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    ke2.server_mac[0] ^= 0xff;

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(matches!(
        result,
        Err(OpaqueError::ServerAuthenticationError)
    ));
}

// --- Tampering detection: KE1 client keyshare ---

#[test]
fn tampered_ke1_keyshare_detected() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (mut ke1, _client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();

    // Replace client keyshare with a clearly invalid P-256 point (all 0xFF x-coordinate).
    let mut bad_point = [0xffu8; 33];
    bad_point[0] = 0x02;
    ke1.client_keyshare = bad_point.to_vec();

    // Server should reject the invalid point.
    let result = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    );
    assert!(result.is_err());
}

// --- Explicit identities round-trip ---

#[test]
fn login_roundtrip_with_explicit_identities() {
    let mut rng = rand_core::OsRng;
    let password = b"password123";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, export_key_reg) = reg_state
        .finish(&reg_response, b"alice", b"bob", &mut rng)
        .unwrap();

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user1",
        b"test-context",
        b"alice",
        b"bob",
        &mut rng,
    )
    .unwrap();

    let (ke3, client_session_key, export_key_login) = client_state
        .finish(&ke2, b"test-context", b"alice", b"bob")
        .unwrap();

    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_eq!(client_session_key, server_session_key);
    assert_eq!(export_key_reg, export_key_login);
}
