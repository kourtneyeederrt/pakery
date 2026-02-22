//! CPace ciphersuite trait.

use pake_core::crypto::{CpaceGroup, Hash};

/// Defines a CPace ciphersuite: a prime-order group, hash function, and associated parameters.
pub trait CpaceCiphersuite: Sized + 'static {
    /// The prime-order group used for the protocol.
    type Group: CpaceGroup;
    /// The hash function used for transcript hashing.
    type Hash: Hash;

    /// Domain Separation Identifier, e.g. `b"CPaceRistretto255"`.
    const DSI: &'static [u8];
    /// Hash input block size in bytes (128 for SHA-512).
    const HASH_BLOCK_SIZE: usize;
    /// Field element size in bytes (32 for Ristretto255).
    const FIELD_SIZE_BYTES: usize;
}
