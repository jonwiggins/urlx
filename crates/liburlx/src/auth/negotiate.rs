//! Negotiate (SPNEGO/Kerberos) authentication via GSS-API.
//!
//! Uses the system GSS-API library (MIT Kerberos or Heimdal) to generate
//! SPNEGO tokens for HTTP Negotiate authentication. The caller's Kerberos
//! credential cache (ccache/keytab) provides the credentials.

use libgssapi::context::{ClientCtx, CtxFlags};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};

use super::GssApiDelegation;

/// Initialise a Negotiate (SPNEGO) security context for the given hostname.
///
/// Returns `(context, base64_token)` on success. The `context` should be
/// kept alive for potential mutual-authentication / continuation rounds
/// (not currently used — single-round SPNEGO is the common case).
///
/// # Errors
///
/// Returns an error if GSS-API initialisation fails (e.g. no Kerberos
/// credentials in the cache, or the target service principal cannot be
/// resolved).
pub fn init_negotiate(
    hostname: &str,
    delegation: GssApiDelegation,
) -> Result<(ClientCtx, String), crate::Error> {
    // Build the target service principal name: HTTP@hostname
    let target_name = format!("HTTP@{hostname}");
    let name = Name::new(target_name.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| crate::Error::Auth(format!("GSS-API: failed to import service name: {e}")))?;

    // Acquire default credentials from the Kerberos ccache
    let mut desired_mechs = OidSet::new()
        .map_err(|e| crate::Error::Auth(format!("GSS-API: failed to create OID set: {e}")))?;
    desired_mechs
        .add(&GSS_MECH_KRB5)
        .map_err(|e| crate::Error::Auth(format!("GSS-API: failed to add Kerberos mech: {e}")))?;
    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&desired_mechs))
        .map_err(|e| crate::Error::Auth(format!("GSS-API: failed to acquire credentials: {e}")))?;

    // Build context flags
    let mut flags = CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG;
    match delegation {
        GssApiDelegation::Always => {
            flags |= CtxFlags::GSS_C_DELEG_FLAG;
        }
        GssApiDelegation::Policy => {
            flags |= CtxFlags::GSS_C_DELEG_POLICY_FLAG;
        }
        GssApiDelegation::None => {}
    }

    // Create the client security context
    let mut ctx = ClientCtx::new(Some(cred), name, flags, Some(&GSS_MECH_KRB5));

    // Step the context (first round — usually sufficient for SPNEGO)
    let token = ctx
        .step(None, None)
        .map_err(|e| crate::Error::Auth(format!("GSS-API: context initialisation failed: {e}")))?;

    let token_bytes = token.ok_or_else(|| {
        crate::Error::Auth("GSS-API: no output token from initial context step".to_string())
    })?;

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&*token_bytes);

    Ok((ctx, b64))
}
