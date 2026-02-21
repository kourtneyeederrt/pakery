//! OPAQUE test vectors from draft-irtf-cfrg-opaque.
//!
//! Vectors 1-2: ristretto255 + SHA-512 + IdentityKSF.
//! Vector 1: default identities (public keys)
//! Vector 2: explicit identities (client=alice, server=bob)

use pake_opaque::ciphersuite::Ristretto255Sha512;
use pake_opaque::OpaqueCiphersuite;
use pake_opaque::{
    ClientLogin, ClientRegistration, OpaqueError, RegistrationRequest, ServerLogin,
    ServerRegistration, ServerSetup, KE1,
};

/// Deterministic RNG that returns pre-determined bytes, one scalar at a time.
///
/// For voprf's OprfClient::blind, the RNG is called to sample a random scalar.
/// We feed it exactly the bytes needed for one 64-byte sample (which gets reduced mod order).
struct SequentialRng {
    chunks: Vec<Vec<u8>>,
    index: usize,
    current_chunk: Vec<u8>,
    chunk_offset: usize,
}

impl SequentialRng {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        let current_chunk = if chunks.is_empty() {
            vec![]
        } else {
            chunks[0].clone()
        };
        Self {
            chunks,
            index: 0,
            current_chunk,
            chunk_offset: 0,
        }
    }

    fn from_single(data: &[u8]) -> Self {
        Self::new(vec![data.to_vec()])
    }
}

impl rand_core::RngCore for SequentialRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.chunk_offset >= self.current_chunk.len() {
                self.index += 1;
                if self.index < self.chunks.len() {
                    self.current_chunk = self.chunks[self.index].clone();
                    self.chunk_offset = 0;
                } else {
                    // Pad with zeros if we run out
                    for b in &mut dest[written..] {
                        *b = 0;
                    }
                    return;
                }
            }
            let available = self.current_chunk.len() - self.chunk_offset;
            let needed = dest.len() - written;
            let to_copy = available.min(needed);
            dest[written..written + to_copy].copy_from_slice(
                &self.current_chunk[self.chunk_offset..self.chunk_offset + to_copy],
            );
            self.chunk_offset += to_copy;
            written += to_copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SequentialRng {}

// ==========================================================================
// Test Vector 1: Default identities (empty client_identity, empty server_identity)
// ==========================================================================

mod vector1 {
    pub const OPRF_SEED: &str = "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef";
    pub const CREDENTIAL_ID: &str = "31323334";
    pub const PASSWORD: &str = "436f7272656374486f72736542617474657279537461706c65";
    pub const ENVELOPE_NONCE: &str =
        "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec";
    pub const MASKING_NONCE: &str =
        "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d";
    pub const SERVER_PRIVATE_KEY: &str =
        "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d";
    pub const SERVER_PUBLIC_KEY: &str =
        "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
    pub const BLIND_REGISTRATION: &str =
        "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01";
    pub const BLIND_LOGIN: &str =
        "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308";
    pub const CLIENT_NONCE: &str =
        "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc";
    pub const SERVER_NONCE: &str =
        "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1";
    pub const CLIENT_KEYSHARE_SEED: &str =
        "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b";
    pub const SERVER_KEYSHARE_SEED: &str =
        "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f";
    pub const CONTEXT: &str = "4f50415155452d504f43";

    // Intermediates
    pub const OPRF_KEY: &str = "5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05";
    pub const _RANDOMIZED_PWD: &str = "aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adeea73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9";
    pub const CLIENT_PUBLIC_KEY: &str =
        "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675";
    pub const MASKING_KEY: &str = "1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5";
    pub const _AUTH_KEY: &str = "6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494fc555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822";
    pub const ENVELOPE: &str = "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5";

    // Outputs
    pub const REGISTRATION_REQUEST: &str =
        "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71";
    pub const REGISTRATION_RESPONSE: &str = "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
    pub const REGISTRATION_UPLOAD: &str = "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5";
    pub const KE1_HEX: &str = "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326";
    pub const KE2_HEX: &str = "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90";
    pub const KE3_HEX: &str = "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442";
    pub const EXPORT_KEY: &str = "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16";
    pub const SESSION_KEY: &str = "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f";

    pub const CLIENT_IDENTITY: &str = "";
    pub const SERVER_IDENTITY: &str = "";
}

// ==========================================================================
// Vector 2: Explicit identities (client=alice, server=bob)
// ==========================================================================

mod vector2 {
    pub const CLIENT_IDENTITY: &str = "616c696365";
    pub const SERVER_IDENTITY: &str = "626f62";

    // Same inputs
    pub use super::vector1::{
        BLIND_LOGIN, BLIND_REGISTRATION, CLIENT_KEYSHARE_SEED, CLIENT_NONCE, CONTEXT,
        CREDENTIAL_ID, ENVELOPE_NONCE, MASKING_NONCE, OPRF_SEED, PASSWORD, SERVER_KEYSHARE_SEED,
        SERVER_NONCE, SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY,
    };

    // Different registration_upload (different envelope)
    pub const REGISTRATION_UPLOAD: &str = "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b680b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c";

    // Same KE1 (identity not involved in KE1)
    pub use super::vector1::KE1_HEX;

    // Different KE2, KE3, session_key
    pub const KE2_HEX: &str = "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fea502150b67fe36795dd8914f164e49f81c7688a38928372134b7dccd50e09f8fed9518b7b2f94835b3c4fe4c8475e7513f20eb97ff0568a39caee3fd6251876f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a292371e7809a9031743e943fb3b56f51de903552fc91fba4e7419029951c3970b2e2f0a9dea218d22e9e4e0000855bb6421aa3610d6fc0f4033a6517030d4341";
    pub const KE3_HEX: &str = "7a026de1d6126905736c3f6d92463a08d209833eb793e46d0f7f15b3e0f62c7643763c02bbc6b8d3d15b63250cae98171e9260f1ffa789750f534ac11a0176d5";
    pub const SESSION_KEY: &str = "ae7951123ab5befc27e62e63f52cf472d6236cb386c968cc47b7e34f866aa4bc7638356a73cfce92becf39d6a7d32a1861f12130e824241fe6cab34fbd471a57";
    pub const EXPORT_KEY: &str = "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16";
}

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

// ==========================================================================
// Tests using vector 1
// ==========================================================================

#[test]
fn test_triple_dh_and_key_derivation() {
    let expected_server_mac_key = "0d36b26cfe38f51f804f0a9361818f32ee1ce2a4e5578653b527184af058d3b2d8075c296fd84d24677913d1baa109290cd81a13ed383f9091a3804e65298dfc";
    let expected_client_mac_key = "91750adbac54a5e8e53b4c233cc8d369fe83b0de1b6a3cd85575eeb0bb01a6a90a086a2cf5fe75fff2a9379c30ba9049510a33b5b0b1444a88800fc3eee2260d";
    let expected_session_key = vector1::SESSION_KEY;

    // Derive the ephemeral keypairs
    let (server_eph_sk, _) =
        Ristretto255Sha512::derive_dh_keypair(&h(vector1::SERVER_KEYSHARE_SEED)).unwrap();
    let (_, client_eph_pk) =
        Ristretto255Sha512::derive_dh_keypair(&h(vector1::CLIENT_KEYSHARE_SEED)).unwrap();

    // Server-side TripleDH
    let server_sk = h(vector1::SERVER_PRIVATE_KEY);
    let client_pk = h(vector1::CLIENT_PUBLIC_KEY);

    let ikm = pake_opaque::key_derivation::triple_dh_ikm::<Ristretto255Sha512>(
        &server_eph_sk,
        &client_eph_pk,
        &server_sk,
        &client_eph_pk,
        &server_eph_sk,
        &client_pk,
    )
    .unwrap();

    // Build preamble (default identities = public keys)
    let server_pub = h(vector1::SERVER_PUBLIC_KEY);
    let context = h(vector1::CONTEXT);
    let ke1_bytes = h(vector1::KE1_HEX);
    let ke2_bytes = h(vector1::KE2_HEX);
    let inner_ke2 = &ke2_bytes[..ke2_bytes.len() - 64];

    let preamble = pake_opaque::key_derivation::build_preamble(
        &context,
        &client_pk,
        &ke1_bytes,
        &server_pub,
        inner_ke2,
    );

    // Derive keys
    let (km2, km3, session_key) =
        pake_opaque::key_derivation::derive_keys::<Ristretto255Sha512>(&ikm, &preamble).unwrap();

    assert_eq!(hex::encode(&km2), expected_server_mac_key);
    assert_eq!(hex::encode(&km3), expected_client_mac_key);
    assert_eq!(hex::encode(&session_key), expected_session_key);
}

#[test]
fn test_oprf_key_derivation() {
    let oprf_key = pake_opaque::oprf::derive_oprf_key::<Ristretto255Sha512>(
        &h(vector1::OPRF_SEED),
        &h(vector1::CREDENTIAL_ID),
    )
    .unwrap();
    assert_eq!(hex::encode(&oprf_key), vector1::OPRF_KEY);
}

#[test]
fn test_registration_request() {
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, _state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut rng).unwrap();

    assert_eq!(
        hex::encode(request.serialize()),
        vector1::REGISTRATION_REQUEST
    );
}

#[test]
fn test_registration_response() {
    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );
    let request = RegistrationRequest {
        blinded_message: h(vector1::REGISTRATION_REQUEST),
    };

    let response = ServerRegistration::<Ristretto255Sha512>::start(
        &setup,
        &request,
        &h(vector1::CREDENTIAL_ID),
    )
    .unwrap();

    assert_eq!(
        hex::encode(response.serialize()),
        vector1::REGISTRATION_RESPONSE
    );
}

#[test]
fn test_intermediate_values() {
    // Verify intermediate values by checking registration record outputs
    // which depend on randomized_password, masking_key, auth_key, etc.
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut rng).unwrap();

    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let response = ServerRegistration::<Ristretto255Sha512>::start(
        &setup,
        &request,
        &h(vector1::CREDENTIAL_ID),
    )
    .unwrap();

    let (record, export_key) = state
        .finish_with_nonce(
            &response,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    // These verify the entire chain: OPRF → randomized_pwd → auth_key/masking_key/envelope
    assert_eq!(
        hex::encode(&record.client_public_key),
        vector1::CLIENT_PUBLIC_KEY
    );
    assert_eq!(hex::encode(&record.masking_key), vector1::MASKING_KEY);
    assert_eq!(hex::encode(record.envelope.serialize()), vector1::ENVELOPE);
    assert_eq!(hex::encode(&export_key), vector1::EXPORT_KEY);
}

#[test]
fn test_registration_record() {
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut rng).unwrap();

    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let response = ServerRegistration::<Ristretto255Sha512>::start(
        &setup,
        &request,
        &h(vector1::CREDENTIAL_ID),
    )
    .unwrap();

    let (record, export_key) = state
        .finish_with_nonce(
            &response,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    assert_eq!(
        hex::encode(record.serialize()),
        vector1::REGISTRATION_UPLOAD
    );
    assert_eq!(hex::encode(&export_key), vector1::EXPORT_KEY);
    assert_eq!(
        hex::encode(&record.client_public_key),
        vector1::CLIENT_PUBLIC_KEY
    );
    assert_eq!(hex::encode(&record.masking_key), vector1::MASKING_KEY);
    assert_eq!(hex::encode(record.envelope.serialize()), vector1::ENVELOPE);
}

#[test]
fn test_ke1() {
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_LOGIN);
    let mut blind_rng = SequentialRng::from_single(&blind);

    let (ke1, _state) = ClientLogin::<Ristretto255Sha512>::start_with_blind_and_nonce_and_seed(
        &password,
        &mut blind_rng,
        &h(vector1::CLIENT_NONCE),
        &h(vector1::CLIENT_KEYSHARE_SEED),
    )
    .unwrap();

    assert_eq!(hex::encode(ke1.serialize()), vector1::KE1_HEX);
}

#[test]
fn test_ke2() {
    // First do registration to get the record
    let password = h(vector1::PASSWORD);
    let blind_reg = h(vector1::BLIND_REGISTRATION);
    let mut reg_rng = SequentialRng::from_single(&blind_reg);

    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let (req, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut reg_rng).unwrap();

    let reg_resp =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &req, &h(vector1::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = reg_state
        .finish_with_nonce(
            &reg_resp,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    // Now do login
    let ke1 = KE1::deserialize::<Ristretto255Sha512>(&h(vector1::KE1_HEX)).unwrap();

    let (ke2, _server_state) = ServerLogin::<Ristretto255Sha512>::start_with_nonce_and_seed(
        &setup,
        &record,
        &ke1,
        &h(vector1::CREDENTIAL_ID),
        &h(vector1::CONTEXT),
        &h(vector1::SERVER_IDENTITY),
        &h(vector1::CLIENT_IDENTITY),
        &h(vector1::SERVER_NONCE),
        &h(vector1::SERVER_KEYSHARE_SEED),
        &h(vector1::MASKING_NONCE),
    )
    .unwrap();

    assert_eq!(hex::encode(ke2.serialize()), vector1::KE2_HEX);
}

#[test]
fn test_ke3_and_session_key() {
    // Full registration
    let password = h(vector1::PASSWORD);
    let blind_reg = h(vector1::BLIND_REGISTRATION);
    let mut reg_rng = SequentialRng::from_single(&blind_reg);

    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let (req, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut reg_rng).unwrap();

    let reg_resp =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &req, &h(vector1::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = reg_state
        .finish_with_nonce(
            &reg_resp,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    // Client login start
    let blind_login = h(vector1::BLIND_LOGIN);
    let mut blind_rng = SequentialRng::from_single(&blind_login);

    let (ke1, client_state) =
        ClientLogin::<Ristretto255Sha512>::start_with_blind_and_nonce_and_seed(
            &password,
            &mut blind_rng,
            &h(vector1::CLIENT_NONCE),
            &h(vector1::CLIENT_KEYSHARE_SEED),
        )
        .unwrap();

    // Server login start
    let (ke2, server_state) = ServerLogin::<Ristretto255Sha512>::start_with_nonce_and_seed(
        &setup,
        &record,
        &ke1,
        &h(vector1::CREDENTIAL_ID),
        &h(vector1::CONTEXT),
        &h(vector1::SERVER_IDENTITY),
        &h(vector1::CLIENT_IDENTITY),
        &h(vector1::SERVER_NONCE),
        &h(vector1::SERVER_KEYSHARE_SEED),
        &h(vector1::MASKING_NONCE),
    )
    .unwrap();

    // Client login finish
    let (ke3, client_session_key, client_export_key) = client_state
        .finish(
            &ke2,
            &h(vector1::CONTEXT),
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
        )
        .unwrap();

    assert_eq!(hex::encode(ke3.serialize()), vector1::KE3_HEX);
    assert_eq!(
        hex::encode(client_session_key.as_bytes()),
        vector1::SESSION_KEY
    );
    assert_eq!(hex::encode(&client_export_key), vector1::EXPORT_KEY);

    // Server login finish
    let server_session_key = server_state.finish(&ke3).unwrap();
    assert_eq!(
        hex::encode(server_session_key.as_bytes()),
        vector1::SESSION_KEY
    );
}

// ==========================================================================
// Tests using vector 2 (explicit identities)
// ==========================================================================

#[test]
fn test_vector2_registration_record() {
    let password = h(vector2::PASSWORD);
    let blind = h(vector2::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut rng).unwrap();

    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector2::OPRF_SEED),
        h(vector2::SERVER_PRIVATE_KEY),
        h(vector2::SERVER_PUBLIC_KEY),
    );

    let response = ServerRegistration::<Ristretto255Sha512>::start(
        &setup,
        &request,
        &h(vector2::CREDENTIAL_ID),
    )
    .unwrap();

    let (record, export_key) = state
        .finish_with_nonce(
            &response,
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
            &h(vector2::ENVELOPE_NONCE),
        )
        .unwrap();

    assert_eq!(
        hex::encode(record.serialize()),
        vector2::REGISTRATION_UPLOAD
    );
    assert_eq!(hex::encode(&export_key), vector2::EXPORT_KEY);
}

#[test]
fn test_vector2_full_login() {
    // Registration
    let password = h(vector2::PASSWORD);
    let blind_reg = h(vector2::BLIND_REGISTRATION);
    let mut reg_rng = SequentialRng::from_single(&blind_reg);

    let setup = ServerSetup::<Ristretto255Sha512>::new_with_key(
        h(vector2::OPRF_SEED),
        h(vector2::SERVER_PRIVATE_KEY),
        h(vector2::SERVER_PUBLIC_KEY),
    );

    let (req, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(&password, &mut reg_rng).unwrap();

    let reg_resp =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &req, &h(vector2::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = reg_state
        .finish_with_nonce(
            &reg_resp,
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
            &h(vector2::ENVELOPE_NONCE),
        )
        .unwrap();

    // Client login start
    let blind_login = h(vector2::BLIND_LOGIN);
    let mut blind_rng = SequentialRng::from_single(&blind_login);

    let (ke1, client_state) =
        ClientLogin::<Ristretto255Sha512>::start_with_blind_and_nonce_and_seed(
            &password,
            &mut blind_rng,
            &h(vector2::CLIENT_NONCE),
            &h(vector2::CLIENT_KEYSHARE_SEED),
        )
        .unwrap();

    assert_eq!(hex::encode(ke1.serialize()), vector2::KE1_HEX);

    // Server login start
    let (ke2, server_state) = ServerLogin::<Ristretto255Sha512>::start_with_nonce_and_seed(
        &setup,
        &record,
        &ke1,
        &h(vector2::CREDENTIAL_ID),
        &h(vector2::CONTEXT),
        &h(vector2::SERVER_IDENTITY),
        &h(vector2::CLIENT_IDENTITY),
        &h(vector2::SERVER_NONCE),
        &h(vector2::SERVER_KEYSHARE_SEED),
        &h(vector2::MASKING_NONCE),
    )
    .unwrap();

    assert_eq!(hex::encode(ke2.serialize()), vector2::KE2_HEX);

    // Client login finish
    let (ke3, client_session_key, client_export_key) = client_state
        .finish(
            &ke2,
            &h(vector2::CONTEXT),
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
        )
        .unwrap();

    assert_eq!(hex::encode(ke3.serialize()), vector2::KE3_HEX);
    assert_eq!(
        hex::encode(client_session_key.as_bytes()),
        vector2::SESSION_KEY
    );
    assert_eq!(hex::encode(&client_export_key), vector2::EXPORT_KEY);

    // Server login finish
    let server_session_key = server_state.finish(&ke3).unwrap();
    assert_eq!(
        hex::encode(server_session_key.as_bytes()),
        vector2::SESSION_KEY
    );
}

// ==========================================================================
// Error / roundtrip tests
// ==========================================================================

#[test]
fn test_full_roundtrip_random() {
    let mut rng = rand_core::OsRng;
    let password = b"correct horse battery staple";

    // Server setup
    let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng).unwrap();

    // Registration
    let (reg_request, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(password, &mut rng).unwrap();

    let reg_response =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &reg_request, b"user123").unwrap();

    let (record, export_key_reg) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    // Login
    let (ke1, client_state) = ClientLogin::<Ristretto255Sha512>::start(password, &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<Ristretto255Sha512>::start(
        &setup,
        &record,
        &ke1,
        b"user123",
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

    // Both sides should agree on the session key
    assert_eq!(client_session_key, server_session_key);
    // Export keys should match between registration and login
    assert_eq!(export_key_reg, export_key_login);
}

#[test]
fn test_wrong_password() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng).unwrap();

    // Register with password A
    let (reg_request, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(b"password-A", &mut rng).unwrap();

    let reg_response =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &reg_request, b"user123").unwrap();

    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    // Try to login with password B
    let (ke1, client_state) =
        ClientLogin::<Ristretto255Sha512>::start(b"password-B", &mut rng).unwrap();

    let (ke2, _server_state) = ServerLogin::<Ristretto255Sha512>::start(
        &setup, &record, &ke1, b"user123", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(matches!(result, Err(OpaqueError::EnvelopeRecoveryError)));
}

#[test]
fn test_tampered_server_mac() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &reg_request, b"user123").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<Ristretto255Sha512>::start(b"password", &mut rng).unwrap();

    let (mut ke2, _server_state) = ServerLogin::<Ristretto255Sha512>::start(
        &setup, &record, &ke1, b"user123", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    // Tamper with server MAC
    ke2.server_mac[0] ^= 0xff;

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(matches!(
        result,
        Err(OpaqueError::ServerAuthenticationError)
    ));
}

#[test]
fn test_tampered_client_mac() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<Ristretto255Sha512>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<Ristretto255Sha512>::start(&setup, &reg_request, b"user123").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<Ristretto255Sha512>::start(b"password", &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<Ristretto255Sha512>::start(
        &setup, &record, &ke1, b"user123", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    let (mut ke3, _, _) = client_state.finish(&ke2, b"ctx", b"", b"").unwrap();

    // Tamper with client MAC
    ke3.client_mac[0] ^= 0xff;

    let result = server_state.finish(&ke3);
    assert!(matches!(
        result,
        Err(OpaqueError::ClientAuthenticationError)
    ));
}

// ==========================================================================
// Fake credential response (user enumeration protection) tests
// ==========================================================================

#[test]
fn test_fake_credential_response() {
    use pake_opaque::messages::CredentialResponse;

    let mut rng = rand_core::OsRng;
    let password = b"some password";

    let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng).unwrap();

    let (ke1, _client_state) =
        ClientLogin::<Ristretto255Sha512>::start(password, &mut rng).unwrap();

    let fake_ke2 = ServerLogin::<Ristretto255Sha512>::start_fake(
        &setup,
        &ke1,
        b"nonexistent_user",
        b"test-context",
        &mut rng,
    )
    .unwrap();

    // Verify KE2 has correct size: Noe + Nn + (Npk + Nn + Nm) + Nn + Npk + Nm
    let expected_size = Ristretto255Sha512::NOE
        + Ristretto255Sha512::NN
        + CredentialResponse::size::<Ristretto255Sha512>()
        + Ristretto255Sha512::NN
        + Ristretto255Sha512::NPK
        + Ristretto255Sha512::NM;
    assert_eq!(fake_ke2.serialize().len(), expected_size);
}

#[test]
fn test_fake_credential_client_fails() {
    let mut rng = rand_core::OsRng;
    let password = b"some password";

    let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng).unwrap();

    // Client starts login normally
    let (ke1, client_state) = ClientLogin::<Ristretto255Sha512>::start(password, &mut rng).unwrap();

    // Server generates fake response (user doesn't exist)
    let fake_ke2 = ServerLogin::<Ristretto255Sha512>::start_fake(
        &setup,
        &ke1,
        b"nonexistent_user",
        b"test-context",
        &mut rng,
    )
    .unwrap();

    // Client should fail at envelope recovery
    let result = client_state.finish(&fake_ke2, b"test-context", b"", b"");
    assert!(matches!(result, Err(OpaqueError::EnvelopeRecoveryError)));
}

// ==========================================================================
// Argon2id ciphersuite tests
// ==========================================================================

#[cfg(feature = "argon2")]
mod argon2_tests {
    use pake_opaque::{
        ClientLogin, ClientRegistration, OpaqueError, Ristretto255Sha512Argon2, ServerLogin,
        ServerRegistration, ServerSetup,
    };

    #[test]
    fn test_argon2_roundtrip() {
        let mut rng = rand_core::OsRng;
        let password = b"correct horse battery staple";

        let setup = ServerSetup::<Ristretto255Sha512Argon2>::new(&mut rng).unwrap();

        // Registration
        let (reg_request, reg_state) =
            ClientRegistration::<Ristretto255Sha512Argon2>::start(password, &mut rng).unwrap();

        let reg_response =
            ServerRegistration::<Ristretto255Sha512Argon2>::start(&setup, &reg_request, b"user123")
                .unwrap();

        let (record, export_key_reg) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

        // Login
        let (ke1, client_state) =
            ClientLogin::<Ristretto255Sha512Argon2>::start(password, &mut rng).unwrap();

        let (ke2, server_state) = ServerLogin::<Ristretto255Sha512Argon2>::start(
            &setup,
            &record,
            &ke1,
            b"user123",
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

    #[test]
    fn test_argon2_wrong_password() {
        let mut rng = rand_core::OsRng;

        let setup = ServerSetup::<Ristretto255Sha512Argon2>::new(&mut rng).unwrap();

        // Register with password A
        let (reg_request, reg_state) =
            ClientRegistration::<Ristretto255Sha512Argon2>::start(b"password-A", &mut rng).unwrap();

        let reg_response =
            ServerRegistration::<Ristretto255Sha512Argon2>::start(&setup, &reg_request, b"user123")
                .unwrap();

        let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

        // Try to login with password B
        let (ke1, client_state) =
            ClientLogin::<Ristretto255Sha512Argon2>::start(b"password-B", &mut rng).unwrap();

        let (ke2, _server_state) = ServerLogin::<Ristretto255Sha512Argon2>::start(
            &setup, &record, &ke1, b"user123", b"ctx", b"", b"", &mut rng,
        )
        .unwrap();

        let result = client_state.finish(&ke2, b"ctx", b"", b"");
        assert!(matches!(result, Err(OpaqueError::EnvelopeRecoveryError)));
    }
}
