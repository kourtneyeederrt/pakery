//! SPAKE2+-specific error types.

use core::fmt;

/// Errors that can occur during SPAKE2+ protocol execution.
#[derive(Debug)]
pub enum Spake2PlusError {
    /// A received point could not be decoded as a valid group element.
    InvalidPoint,
    /// A computed or received point is the group identity element.
    IdentityPoint,
    /// MAC confirmation of the peer's key failed.
    ConfirmationFailed,
    /// An internal protocol error occurred.
    InternalError(&'static str),
}

impl fmt::Display for Spake2PlusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Spake2PlusError::InvalidPoint => write!(f, "invalid point encoding"),
            Spake2PlusError::IdentityPoint => write!(f, "identity point encountered"),
            Spake2PlusError::ConfirmationFailed => write!(f, "key confirmation failed"),
            Spake2PlusError::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Spake2PlusError {}

impl From<pake_core::PakeError> for Spake2PlusError {
    fn from(e: pake_core::PakeError) -> Self {
        match e {
            pake_core::PakeError::InvalidPoint => Spake2PlusError::InvalidPoint,
            pake_core::PakeError::IdentityPoint => Spake2PlusError::IdentityPoint,
            pake_core::PakeError::ProtocolError(msg) => Spake2PlusError::InternalError(msg),
            pake_core::PakeError::InvalidInput(msg) => Spake2PlusError::InternalError(msg),
        }
    }
}

impl From<Spake2PlusError> for pake_core::PakeError {
    fn from(e: Spake2PlusError) -> Self {
        match e {
            Spake2PlusError::InvalidPoint => pake_core::PakeError::InvalidPoint,
            Spake2PlusError::IdentityPoint => pake_core::PakeError::IdentityPoint,
            Spake2PlusError::ConfirmationFailed => {
                pake_core::PakeError::ProtocolError("key confirmation failed")
            }
            Spake2PlusError::InternalError(msg) => pake_core::PakeError::ProtocolError(msg),
        }
    }
}
