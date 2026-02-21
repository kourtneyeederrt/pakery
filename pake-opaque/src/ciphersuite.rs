//! OPAQUE ciphersuite trait and concrete implementations.

use crate::error::OpaqueError;
use crate::key_stretch::KeyStretchingFunction;
use rand_core::CryptoRngCore;

/// Trait defining the cryptographic primitives for an OPAQUE ciphersuite.
///
/// Constants follow RFC 9807 naming: Nn (nonce), Nseed (seed), Noe (OPRF element),
/// Nok (OPRF key), Nm (MAC), Nh (hash), Npk (public key), Nsk (secret key), Nx (KDF extract).
pub trait OpaqueCiphersuite: Sized + 'static {
    /// The OPRF ciphersuite type from the `voprf` crate.
    type OprfCs: voprf::CipherSuite;
    /// The hash function used throughout.
    type Hash: digest::Digest + Clone;
    /// The key stretching function.
    type Ksf: KeyStretchingFunction;

    /// Nonce length in bytes.
    const NN: usize;
    /// Seed length in bytes.
    const NSEED: usize;
    /// OPRF serialized element length in bytes.
    const NOE: usize;
    /// OPRF scalar/key length in bytes.
    const NOK: usize;
    /// MAC output length in bytes.
    const NM: usize;
    /// Hash output length in bytes.
    const NH: usize;
    /// Public key length in bytes.
    const NPK: usize;
    /// Secret key length in bytes.
    const NSK: usize;
    /// KDF extract output length in bytes.
    const NX: usize;

    /// KDF-Extract(salt, ikm) — HKDF-Extract.
    fn kdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8>;
    /// KDF-Expand(prk, info, len) — HKDF-Expand.
    fn kdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, OpaqueError>;
    /// MAC(key, msg) — keyed MAC.
    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, OpaqueError>;
    /// Constant-time MAC verification.
    fn mac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), OpaqueError>;
    /// Hash(input).
    fn hash(input: &[u8]) -> Vec<u8>;
    /// Scalar multiplication / Diffie-Hellman: sk * pk.
    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, OpaqueError>;
    /// Derive a DH keypair deterministically from a seed.
    fn derive_dh_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OpaqueError>;
    /// Generate a random authentication keypair.
    fn generate_auth_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError>;
    /// Serialize a public key from a private key.
    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, OpaqueError>;
}

/// Ristretto255 + SHA-512 ciphersuite for OPAQUE.
#[cfg(feature = "ristretto255")]
pub struct Ristretto255Sha512;

#[cfg(feature = "ristretto255")]
impl OpaqueCiphersuite for Ristretto255Sha512 {
    type OprfCs = voprf::Ristretto255;
    type Hash = sha2::Sha512;
    type Ksf = crate::key_stretch::IdentityKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 32;
    const NOK: usize = 32;
    const NM: usize = 64;
    const NH: usize = 64;
    const NPK: usize = 32;
    const NSK: usize = 32;
    const NX: usize = 64;

    fn kdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        use hkdf::Hkdf;
        let (prk, _) = Hkdf::<sha2::Sha512>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn kdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, OpaqueError> {
        use hkdf::Hkdf;
        let hkdf = Hkdf::<sha2::Sha512>::from_prk(prk)
            .map_err(|_| OpaqueError::InternalError("invalid PRK length"))?;
        let mut output = vec![0u8; len];
        hkdf.expand(info, &mut output)
            .map_err(|_| OpaqueError::InternalError("HKDF expand failed"))?;
        Ok(output)
    }

    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(key)
            .map_err(|_| OpaqueError::InternalError("HMAC key rejected"))?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn mac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), OpaqueError> {
        use subtle::ConstantTimeEq;
        let computed = Self::mac(key, msg)?;
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(OpaqueError::InvalidMac)
        }
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use digest::Digest;
        let mut hasher = sha2::Sha512::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }

    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        use curve25519_dalek::traits::Identity;
        let sk_bytes: [u8; 32] = sk
            .try_into()
            .map_err(|_| OpaqueError::InvalidInput("invalid secret key length"))?;
        let scalar = curve25519_dalek::Scalar::from_canonical_bytes(sk_bytes)
            .into_option()
            .ok_or(OpaqueError::InvalidInput("invalid scalar"))?;

        let pk_bytes: [u8; 32] = pk
            .try_into()
            .map_err(|_| OpaqueError::InvalidInput("invalid public key length"))?;
        let pk_point = curve25519_dalek::ristretto::CompressedRistretto(pk_bytes)
            .decompress()
            .ok_or(OpaqueError::InvalidInput("invalid public key point"))?;

        let result = scalar * pk_point;
        if result == curve25519_dalek::RistrettoPoint::identity() {
            return Err(OpaqueError::InternalError("DH result is identity"));
        }
        Ok(result.compress().to_bytes().to_vec())
    }

    fn derive_dh_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        // Use OPRF DeriveKeyPair with OPAQUE-specific info string
        let server = voprf::OprfServer::<voprf::Ristretto255>::new_from_seed(
            seed,
            b"OPAQUE-DeriveDiffieHellmanKeyPair",
        )
        .map_err(|_| OpaqueError::InternalError("DeriveKeyPair failed"))?;

        let sk_bytes = server.serialize().to_vec();
        let sk_arr: [u8; 32] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| OpaqueError::InternalError("invalid key size"))?;
        let scalar = curve25519_dalek::Scalar::from_canonical_bytes(sk_arr)
            .into_option()
            .ok_or(OpaqueError::InternalError(
                "invalid scalar from DeriveKeyPair",
            ))?;

        let pk = (scalar * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes()
            .to_vec();
        Ok((sk_bytes, pk))
    }

    fn generate_auth_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::derive_dh_keypair(&seed)
    }

    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let sk_bytes: [u8; 32] = sk
            .try_into()
            .map_err(|_| OpaqueError::InvalidInput("invalid secret key length"))?;
        let scalar = curve25519_dalek::Scalar::from_canonical_bytes(sk_bytes)
            .into_option()
            .ok_or(OpaqueError::InvalidInput("invalid scalar"))?;
        let pk = (scalar * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes()
            .to_vec();
        Ok(pk)
    }
}

/// Ristretto255 + SHA-512 + Argon2id ciphersuite for production use.
#[cfg(all(feature = "ristretto255", feature = "argon2"))]
pub struct Ristretto255Sha512Argon2;

#[cfg(all(feature = "ristretto255", feature = "argon2"))]
impl OpaqueCiphersuite for Ristretto255Sha512Argon2 {
    type OprfCs = voprf::Ristretto255;
    type Hash = sha2::Sha512;
    type Ksf = crate::key_stretch::Argon2idKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 32;
    const NOK: usize = 32;
    const NM: usize = 64;
    const NH: usize = 64;
    const NPK: usize = 32;
    const NSK: usize = 32;
    const NX: usize = 64;

    fn kdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        Ristretto255Sha512::kdf_extract(salt, ikm)
    }

    fn kdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, OpaqueError> {
        Ristretto255Sha512::kdf_expand(prk, info, len)
    }

    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        Ristretto255Sha512::mac(key, msg)
    }

    fn mac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), OpaqueError> {
        Ristretto255Sha512::mac_verify(key, msg, tag)
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        Ristretto255Sha512::hash(input)
    }

    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        Ristretto255Sha512::diffie_hellman(sk, pk)
    }

    fn derive_dh_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        Ristretto255Sha512::derive_dh_keypair(seed)
    }

    fn generate_auth_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
        Ristretto255Sha512::generate_auth_keypair(rng)
    }

    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        Ristretto255Sha512::public_key_from_private(sk)
    }
}
