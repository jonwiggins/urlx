//! HTTP Negotiate (SPNEGO/Kerberos) authentication.
//!
//! Implements the client side of the SPNEGO authentication mechanism
//! (RFC 4559) using the system GSS-API library. This enables Kerberos
//! single sign-on for HTTP and proxy authentication.
//!
//! Requires the `gss-api` feature flag and system Kerberos libraries
//! (MIT Kerberos or Heimdal).

use super::GssApiDelegation;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE},
};

/// State for an in-progress Negotiate (SPNEGO) authentication exchange.
pub struct NegotiateContext {
    ctx: ClientCtx,
}

impl std::fmt::Debug for NegotiateContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegotiateContext").field("complete", &self.ctx.is_complete()).finish()
    }
}

/// Create the initial Negotiate token for the given hostname.
///
/// Returns a `(context, base64_token)` pair.
///
/// # Errors
///
/// Returns an error if no valid Kerberos credentials are available.
pub fn init_negotiate(
    hostname: &str,
    delegation: GssApiDelegation,
) -> Result<(NegotiateContext, String), String> {
    let service_name = format!("HTTP@{hostname}");
    let target = Name::new(service_name.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| format!("GSS-API: failed to import service name: {e}"))?;

    let desired_mechs = {
        let mut s = OidSet::new().map_err(|e| format!("GSS-API: failed to create OID set: {e}"))?;
        s.add(&GSS_MECH_SPNEGO).map_err(|e| format!("GSS-API: failed to add SPNEGO OID: {e}"))?;
        s
    };
    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&desired_mechs))
        .map_err(|e| format!("GSS-API: failed to acquire credentials: {e}"))?;

    let mut flags = CtxFlags::GSS_C_MUTUAL_FLAG;
    match delegation {
        GssApiDelegation::None => {}
        GssApiDelegation::Policy => {
            flags |= CtxFlags::GSS_C_DELEG_POLICY_FLAG;
        }
        GssApiDelegation::Always => {
            flags |= CtxFlags::GSS_C_DELEG_FLAG;
        }
    }

    let mut ctx = ClientCtx::new(Some(cred), target, flags, Some(&GSS_MECH_SPNEGO));

    let token =
        ctx.step(None, None).map_err(|e| format!("GSS-API: initial context step failed: {e}"))?;

    token.map_or_else(
        || Err("GSS-API: no output token from initial step".to_string()),
        |tok| {
            let b64 = BASE64.encode(&*tok);
            Ok((NegotiateContext { ctx }, b64))
        },
    )
}

/// Process a server challenge token and produce the next client token.
///
/// # Errors
///
/// Returns an error if the server token is invalid.
pub fn process_challenge(
    negotiate_ctx: &mut NegotiateContext,
    server_token_b64: &str,
) -> Result<Option<String>, String> {
    let server_token = BASE64
        .decode(server_token_b64)
        .map_err(|e| format!("GSS-API: invalid base64 in server token: {e}"))?;

    let token = negotiate_ctx
        .ctx
        .step(Some(&server_token), None)
        .map_err(|e| format!("GSS-API: context step failed: {e}"))?;

    Ok(token.map(|tok| BASE64.encode(&*tok)))
}

/// Check if the Negotiate context has completed authentication.
#[must_use]
pub fn is_complete(negotiate_ctx: &NegotiateContext) -> bool {
    negotiate_ctx.ctx.is_complete()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_default_is_none() {
        assert_eq!(GssApiDelegation::default(), GssApiDelegation::None);
    }

    #[test]
    fn test_init_negotiate_fails_without_credentials() {
        let result = init_negotiate("example.com", GssApiDelegation::None);
        assert!(result.is_err(), "should fail without Kerberos env");
        if let Err(err) = result {
            assert!(err.contains("GSS-API"), "error should mention GSS-API: {err}");
        }
    }

    #[test]
    fn test_init_negotiate_with_delegation_policy() {
        let result = init_negotiate("example.com", GssApiDelegation::Policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_init_negotiate_with_delegation_always() {
        let result = init_negotiate("example.com", GssApiDelegation::Always);
        assert!(result.is_err());
    }
}
