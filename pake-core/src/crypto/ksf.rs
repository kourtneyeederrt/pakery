//! Key stretching function trait.

use crate::error::PakeError;
use alloc::vec::Vec;

/// A key stretching function (KSF) used to harden passwords.
pub trait Ksf {
    /// Stretch the input bytes.
    fn stretch(input: &[u8]) -> Result<Vec<u8>, PakeError>;
}

/// Identity key stretching function (pass-through).
///
/// Used in test vectors; not suitable for production.
pub struct IdentityKsf;

impl Ksf for IdentityKsf {
    fn stretch(input: &[u8]) -> Result<Vec<u8>, PakeError> {
        Ok(input.to_vec())
    }
}
