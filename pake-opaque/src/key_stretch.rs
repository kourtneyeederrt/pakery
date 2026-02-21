//! Key stretching functions for OPAQUE.

use crate::OpaqueError;

/// A key stretching function (KSF) used to harden passwords.
pub trait KeyStretchingFunction {
    /// Stretch the input to the given output length.
    fn stretch(input: &[u8]) -> Result<Vec<u8>, OpaqueError>;
}

/// Identity key stretching function (pass-through).
///
/// Used in test vectors; not suitable for production.
pub struct IdentityKsf;

impl KeyStretchingFunction for IdentityKsf {
    fn stretch(input: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        Ok(input.to_vec())
    }
}

/// Argon2id key stretching function for production use.
#[cfg(feature = "argon2")]
pub struct Argon2idKsf;

#[cfg(feature = "argon2")]
impl KeyStretchingFunction for Argon2idKsf {
    fn stretch(input: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(65536, 3, 4, Some(64))
            .map_err(|_| OpaqueError::InternalError("argon2 params"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = vec![0u8; 64];
        argon2
            .hash_password_into(input, b"OPAQUE-Argon2id", &mut output)
            .map_err(|_| OpaqueError::InternalError("argon2 hash"))?;
        Ok(output)
    }
}
