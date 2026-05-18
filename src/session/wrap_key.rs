//! Machine-bound wrap key derivation for the local session blob.
//!
//! Per ADR-KVD-029: the wrap key is derived from a machine-bound salt
//! (`hostname` + `uid` + `kvendra_home_canonical`) and a fixed sentinel IKM.
//! It is **not** derived from the master password — the session blob already
//! stores the derived key as payload; using the master password as IKM would
//! introduce a chicken-and-egg dependency for the very prompt the blob is
//! meant to avoid.
//!
//! Sub-key namespace follows ADR-KVD-022 (`kvendra/<purpose>/v<N>`): the
//! info constant is `kvendra/session-wrap/v1`, the fourth alive sub-key
//! after audit-hmac/v1, allowlist-hmac/v1 and config-hmac/v1.

use crate::error::{KvendraError, KvendraResult};
use hkdf::Hkdf;
use sha2::Sha256;
use std::path::{Path, PathBuf};

/// HKDF info string for the session wrap key. Domain-separates this key from
/// other sub-keys derived from any common PRK. See ADR-KVD-022.
pub const HKDF_INFO_SESSION_WRAP: &[u8] = b"kvendra/session-wrap/v1";

/// Sentinel IKM — canonical ASCII for auditability in `THREAT-MODEL.md`.
/// Entropy comes from the machine-bound salt; this constant only namespaces
/// the derivation.
pub const SESSION_WRAP_SENTINEL_IKM: &[u8] = b"kvendra-session-wrap-sentinel-v1";

/// Field separator for the machine salt. Chosen as ASCII Unit Separator
/// (0x1F) so it cannot appear in hostnames, uids or paths.
const SALT_SEPARATOR: u8 = 0x1F;

/// Build the machine-bound salt from its three components. The order is
/// fixed (hostname, uid, kvendra_home_canonical) and forms part of the
/// `kvendra/session-wrap/v1` contract.
pub fn machine_salt(hostname: &str, uid: &str, kvendra_home_canonical: &Path) -> Vec<u8> {
    let mut salt = Vec::with_capacity(
        hostname.len() + uid.len() + kvendra_home_canonical.as_os_str().len() + 2,
    );
    salt.extend_from_slice(hostname.as_bytes());
    salt.push(SALT_SEPARATOR);
    salt.extend_from_slice(uid.as_bytes());
    salt.push(SALT_SEPARATOR);
    salt.extend_from_slice(kvendra_home_canonical.to_string_lossy().as_bytes());
    salt
}

/// Derive the 32-byte session wrap key via HKDF-SHA256.
pub fn derive_wrap_key(salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), SESSION_WRAP_SENTINEL_IKM);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO_SESSION_WRAP, &mut okm)
        .expect("HKDF expand 32 bytes always succeeds");
    okm
}

/// Read the host's name. On POSIX, `gethostname(3)` direct via `libc`. On
/// Windows we fall back to the `COMPUTERNAME` env var — sufficient for the
/// stub-level support documented in ADR-KVD-029 (full Windows validation is
/// pending physical PoC).
pub fn current_hostname() -> KvendraResult<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if rc != 0 {
            return Err(KvendraError::SessionStore(format!(
                "gethostname failed (errno {})",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            )));
        }
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = std::str::from_utf8(&buf[..nul])
            .map_err(|e| KvendraError::SessionStore(format!("hostname utf8: {e}")))?;
        Ok(s.to_string())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME")
            .map_err(|_| KvendraError::SessionStore("COMPUTERNAME env var unset".into()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(KvendraError::SessionStore(
            "current_hostname unsupported on this platform".into(),
        ))
    }
}

/// Read the user's identifier. POSIX `getuid(2)` rendered as decimal string.
/// Windows uses `USERNAME` env var (stub-level — pending full SID lookup in
/// alpha.2).
pub fn current_uid() -> KvendraResult<String> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        Ok(uid.to_string())
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME")
            .map_err(|_| KvendraError::SessionStore("USERNAME env var unset".into()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(KvendraError::SessionStore(
            "current_uid unsupported on this platform".into(),
        ))
    }
}

/// Canonicalize the kvendra home directory (resolve symlinks, absolute
/// path). Used as the third component of the machine-bound salt.
pub fn kvendra_home_canonical(kvendra_home: &Path) -> KvendraResult<PathBuf> {
    std::fs::canonicalize(kvendra_home)
        .map_err(|e| KvendraError::SessionStore(format!("canonicalize home: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn machine_salt_has_separators_in_known_positions() {
        let salt = machine_salt("host", "1000", &PathBuf::from("/home/u/.kvendra"));
        let expected: Vec<u8> = b"host\x1F1000\x1F/home/u/.kvendra".to_vec();
        assert_eq!(salt, expected);
    }

    #[test]
    fn derive_wrap_key_is_deterministic() {
        let salt = machine_salt("h", "u", &PathBuf::from("/p"));
        let k1 = derive_wrap_key(&salt);
        let k2 = derive_wrap_key(&salt);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn derive_wrap_key_differs_per_machine() {
        let s1 = machine_salt(
            "alice-laptop",
            "501",
            &PathBuf::from("/Users/alice/.kvendra"),
        );
        let s2 = machine_salt("bob-laptop", "502", &PathBuf::from("/Users/bob/.kvendra"));
        let k1 = derive_wrap_key(&s1);
        let k2 = derive_wrap_key(&s2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_wrap_key_changes_when_any_salt_component_changes() {
        let base = machine_salt("h", "1", &PathBuf::from("/p"));
        let k_base = derive_wrap_key(&base);

        let host_changed = machine_salt("h2", "1", &PathBuf::from("/p"));
        assert_ne!(derive_wrap_key(&host_changed), k_base);

        let uid_changed = machine_salt("h", "2", &PathBuf::from("/p"));
        assert_ne!(derive_wrap_key(&uid_changed), k_base);

        let home_changed = machine_salt("h", "1", &PathBuf::from("/p2"));
        assert_ne!(derive_wrap_key(&home_changed), k_base);
    }

    #[test]
    fn info_constant_is_canonical_v1() {
        assert_eq!(HKDF_INFO_SESSION_WRAP, b"kvendra/session-wrap/v1");
    }

    #[test]
    fn sentinel_ikm_is_canonical() {
        assert_eq!(
            SESSION_WRAP_SENTINEL_IKM,
            b"kvendra-session-wrap-sentinel-v1"
        );
    }

    #[test]
    fn current_hostname_returns_non_empty() {
        let h = current_hostname().expect("hostname should be readable");
        assert!(!h.is_empty(), "hostname must be non-empty");
    }

    #[test]
    fn current_uid_returns_non_empty() {
        let u = current_uid().expect("uid should be readable");
        assert!(!u.is_empty(), "uid must be non-empty");
    }
}
