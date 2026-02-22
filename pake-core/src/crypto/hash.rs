//! Hash function trait.

use alloc::vec::Vec;

/// A cryptographic hash function.
pub trait Hash: Sized + Clone {
    /// Create a new hasher.
    fn new() -> Self;

    /// Feed data into the hasher.
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the hash digest.
    fn finalize(self) -> Vec<u8>;

    /// One-shot: hash data and return the digest.
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}
