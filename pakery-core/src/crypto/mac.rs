//! Message authentication code trait.

use crate::error::PakeError;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

/// A message authentication code.
pub trait Mac {
    /// Compute a MAC tag.
    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, PakeError>;

    /// Verify a MAC tag in constant time.
    fn verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), PakeError> {
        let computed = Self::mac(key, msg)?;
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(PakeError::ProtocolError("MAC verification failed"))
        }
    }
}
