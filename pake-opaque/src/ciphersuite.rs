//! OPAQUE ciphersuite trait.

use pake_core::crypto::{DhGroup, Hash, Kdf, Ksf, Mac, Oprf};

/// Trait defining the cryptographic primitives for an OPAQUE ciphersuite.
///
/// Constants follow RFC 9807 naming: Nn (nonce), Nseed (seed), Noe (OPRF element),
/// Nok (OPRF key), Nm (MAC), Nh (hash), Npk (public key), Nsk (secret key), Nx (KDF extract).
pub trait OpaqueCiphersuite: Sized + 'static {
    /// The hash function.
    type Hash: Hash;
    /// The key derivation function.
    type Kdf: Kdf;
    /// The message authentication code.
    type Mac: Mac;
    /// The Diffie-Hellman group.
    type Dh: DhGroup;
    /// The oblivious PRF.
    type Oprf: Oprf;
    /// The key stretching function.
    type Ksf: Ksf;

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
}
