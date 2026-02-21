//! Thin wrapper over the `voprf` crate for OPAQUE's OPRF operations.

use crate::ciphersuite::OpaqueCiphersuite;
use crate::OpaqueError;
use rand_core::CryptoRngCore;

/// State held by the client between blind and finalize.
pub struct OprfClientState<C: OpaqueCiphersuite> {
    pub(crate) state: voprf::OprfClient<C::OprfCs>,
}

/// Blind a password for the OPRF protocol.
///
/// Returns the client state (to keep) and the serialized blinded element (to send).
pub fn oprf_client_blind<C: OpaqueCiphersuite>(
    password: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(OprfClientState<C>, Vec<u8>), OpaqueError> {
    let result = voprf::OprfClient::<C::OprfCs>::blind(password, rng)
        .map_err(|_| OpaqueError::InternalError("OPRF blind failed"))?;
    let blinded_bytes = result.message.serialize().to_vec();
    Ok((
        OprfClientState {
            state: result.state,
        },
        blinded_bytes,
    ))
}

/// Finalize the OPRF output on the client side.
pub fn oprf_client_finalize<C: OpaqueCiphersuite>(
    state: &OprfClientState<C>,
    password: &[u8],
    evaluated_bytes: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    let evaluated = voprf::EvaluationElement::<C::OprfCs>::deserialize(evaluated_bytes)
        .map_err(|_| OpaqueError::DeserializationError)?;
    let output = state
        .state
        .finalize(password, &evaluated)
        .map_err(|_| OpaqueError::InternalError("OPRF finalize failed"))?;
    Ok(output.to_vec())
}

/// Server-side OPRF evaluation: evaluate the blinded element with the given key.
pub fn oprf_server_evaluate<C: OpaqueCiphersuite>(
    oprf_key: &[u8],
    blinded_bytes: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    let server = voprf::OprfServer::<C::OprfCs>::new_with_key(oprf_key)
        .map_err(|_| OpaqueError::InternalError("invalid OPRF key"))?;
    let blinded = voprf::BlindedElement::<C::OprfCs>::deserialize(blinded_bytes)
        .map_err(|_| OpaqueError::DeserializationError)?;
    let evaluated = server.blind_evaluate(&blinded);
    Ok(evaluated.serialize().to_vec())
}

/// Derive an OPRF key from the server's oprf_seed and a credential identifier.
///
/// Per RFC 9807:
/// ```text
/// seed = Expand(oprf_seed, concat(credential_id, "OprfKey"), Nseed)
/// (oprf_key, _) = OPRF.DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
/// ```
pub fn derive_oprf_key<C: OpaqueCiphersuite>(
    oprf_seed: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    let mut info = Vec::with_capacity(credential_id.len() + 7);
    info.extend_from_slice(credential_id);
    info.extend_from_slice(b"OprfKey");

    // oprf_seed is used directly as the PRK for HKDF-Expand
    let seed = C::kdf_expand(oprf_seed, &info, C::NSEED)?;

    // Use OPRF DeriveKeyPair to get the actual scalar key
    let server = voprf::OprfServer::<C::OprfCs>::new_from_seed(&seed, b"OPAQUE-DeriveKeyPair")
        .map_err(|_| OpaqueError::InternalError("OPRF DeriveKeyPair failed"))?;
    Ok(server.serialize().to_vec())
}
