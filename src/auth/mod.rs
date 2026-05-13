//! Auth module — OIDC discovery, PKCE Authorization Code flow, and proactive
//! refresh of cached session tokens (REQ-KVD-CLI-004 / REQ-KVD-CLI-008).
//!
//! Cloud-agnostic by construction: no provider-specific strings inside this
//! module. The IdP base URL is `KVENDRA_AUTH_URL` (default
//! `https://auth.kvendra.cloud`) and the OIDC client id comes from
//! `KVENDRA_CLIENT_ID`.

pub mod discovery;
pub mod oidc;
pub mod refresh;

pub use discovery::{OidcConfig, discover};
pub use oidc::{PkceFlow, TokenSet, login_workspace};
pub use refresh::{RefreshOutcome, refresh_if_needed};
