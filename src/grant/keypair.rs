//! ed25519 grant-signing keypair: private seed sealed under the vault key,
//! public key stored in the clear (ISSUE-KVD-CLI-20E747).
//!
//! On-disk layout, both under `~/.kvendra/`:
//!   - `grant_sign.key`  — sealed private seed (AES-256-GCM under the
//!     `kvendra/grant-sign/v1` HKDF sub-key derived from the vault key).
//!     Mode 0600. Decryptable only while the vault is unlocked.
//!   - `grant_sign.pub`  — base64 ed25519 public key (32 bytes). World-
//!     readable by design: `kvendra grant-pubkey` exports it WITHOUT
//!     unlocking the vault (AC-HOOK-3 — the hook pins this to verify).
//!
//! The sealed seed mirrors the `session/local.rs` crypto: a 12-byte random
//! nonce prepended to the AES-256-GCM ciphertext. We do NOT add a separate
//! HMAC sidecar — the GCM tag already authenticates, and unlike the session
//! blob this material is not machine-portable-by-key (the sub-key is bound
//! to the vault master key, not to a machine salt).

use crate::error::{KvendraError, KvendraResult};
use crate::grant::HKDF_INFO_GRANT_SIGN;
use crate::vault::Vault;
use crate::vault::session::hkdf_expand;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Path of the sealed private seed.
pub fn private_key_path(home: &Path) -> PathBuf {
    home.join("grant_sign.key")
}

/// Path of the cleartext public key.
pub fn public_key_path(home: &Path) -> PathBuf {
    home.join("grant_sign.pub")
}

/// Derive the AES key that wraps the ed25519 seed from the vault's
/// `grant-sign/v1` sub-key. Requires the vault to be unlocked.
fn wrap_key(vault: &Vault) -> KvendraResult<[u8; 32]> {
    // The vault exposes its HMAC sub-keys but not an arbitrary HKDF; we
    // re-derive the grant sub-key from the live session's master key via
    // the same `hkdf_expand` the vault uses internally. `peek_session_*`
    // is the only key-bytes accessor, and it already checks unlock/TTL.
    let master = vault.peek_session_derived_key()?;
    let sub = hkdf_expand(&master, HKDF_INFO_GRANT_SIGN);
    let out = *sub.as_bytes();
    // `master` is a stack copy; zeroize it explicitly (the sub-key wrapper
    // zeroizes on drop).
    let mut master = master;
    master.zeroize();
    Ok(out)
}

/// Seal a 32-byte ed25519 seed under the wrap key. Returns
/// `nonce || ciphertext` (the GCM tag is appended by the AEAD).
fn seal_seed(wrap: &[u8; 32], seed: &[u8; SEED_LEN]) -> KvendraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, seed.as_ref())
        .map_err(|e| KvendraError::Vault(format!("grant seed seal: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed seed produced by [`seal_seed`]. A wrong key or any tamper
/// surfaces as a GCM tag failure.
fn open_seed(wrap: &[u8; 32], blob: &[u8]) -> KvendraResult<[u8; SEED_LEN]> {
    if blob.len() <= NONCE_LEN {
        return Err(KvendraError::Vault("grant seed blob truncated".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| {
            KvendraError::Vault("grant seed decrypt failed (tamper or wrong key)".into())
        })?;
    if pt.len() != SEED_LEN {
        return Err(KvendraError::Vault("grant seed wrong length".into()));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&pt);
    Ok(seed)
}

/// Write the sealed private seed (0600) and the cleartext public key.
fn persist(home: &Path, sealed: &[u8], pubkey: &VerifyingKey) -> KvendraResult<()> {
    crate::config::create_dir_secure(home)?;
    let priv_path = private_key_path(home);
    std::fs::write(&priv_path, sealed)?;
    crate::config::set_file_mode_secure(&priv_path)?;

    let pub_path = public_key_path(home);
    std::fs::write(&pub_path, b64().encode(pubkey.to_bytes()))?;
    // Public key need not be 0600, but tightening it is harmless.
    crate::config::set_file_mode_secure(&pub_path)?;
    Ok(())
}

/// Load the public key from `grant_sign.pub` WITHOUT unlocking the vault.
/// This is the read path used by `kvendra grant-pubkey` and the hook
/// verifier (AC-HOOK-3). Returns `ProfileNotFound`-flavoured error when no
/// keypair has been generated yet.
pub fn load_public_key(home: &Path) -> KvendraResult<VerifyingKey> {
    let path = public_key_path(home);
    if !path.exists() {
        return Err(KvendraError::Vault(
            "no grant signing key — run `kvendra bypass ...` once to generate it".into(),
        ));
    }
    let raw = std::fs::read_to_string(&path)?;
    let bytes = b64()
        .decode(raw.trim())
        .map_err(|e| KvendraError::Vault(format!("grant pubkey b64: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| KvendraError::Vault("grant pubkey wrong length".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| KvendraError::Vault(format!("grant pubkey invalid: {e}")))
}

/// Decode an ed25519 public key from its base64 wire form (as emitted by
/// `kvendra grant-pubkey`). Used by the `verify-grant` stdin contract.
pub fn parse_public_key_b64(pubkey_b64: &str) -> KvendraResult<VerifyingKey> {
    let bytes = b64()
        .decode(pubkey_b64.trim())
        .map_err(|e| KvendraError::Vault(format!("grant pubkey b64: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| KvendraError::Vault("grant pubkey wrong length".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| KvendraError::Vault(format!("grant pubkey invalid: {e}")))
}

/// Load the existing keypair, or generate + persist a fresh one if none
/// exists (lazy generation, OQ-5). Requires the vault to be unlocked.
/// Returns the live [`SigningKey`].
pub fn load_or_generate(home: &Path, vault: &Vault) -> KvendraResult<SigningKey> {
    if private_key_path(home).exists() && public_key_path(home).exists() {
        return load_signing_key_impl(home, vault);
    }
    generate(home, vault)
}

/// Generate a fresh keypair and persist it (overwrites any existing one —
/// used by `--rotate-key`). Requires the vault to be unlocked.
pub fn generate(home: &Path, vault: &Vault) -> KvendraResult<SigningKey> {
    let signing = SigningKey::generate(&mut OsRng);
    let mut wrap = wrap_key(vault)?;
    let seed = signing.to_bytes();
    let sealed = seal_seed(&wrap, &seed);
    wrap.zeroize();
    let sealed = sealed?;
    persist(home, &sealed, &signing.verifying_key())?;
    Ok(signing)
}

/// Internal: decrypt the sealed seed and rebuild the [`SigningKey`].
fn load_signing_key_impl(home: &Path, vault: &Vault) -> KvendraResult<SigningKey> {
    let blob = std::fs::read(private_key_path(home))?;
    let mut wrap = wrap_key(vault)?;
    let seed = open_seed(&wrap, &blob);
    wrap.zeroize();
    let mut seed = seed?;
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfParams;
    use tempfile::tempdir;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    fn unlocked_vault(home: &Path) -> Vault {
        crate::config::ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-grant-keypair", fast_params())
            .unwrap();
        v.unlock(b"hunter2-grant-keypair", 30).unwrap();
        v
    }

    #[test]
    fn generate_then_load_roundtrips_same_key() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        let kp = generate(dir.path(), &v).unwrap();
        let loaded = load_signing_key_impl(dir.path(), &v).unwrap();
        assert_eq!(kp.to_bytes(), loaded.to_bytes());
        assert_eq!(
            kp.verifying_key().to_bytes(),
            loaded.verifying_key().to_bytes()
        );
    }

    #[test]
    fn public_key_loads_without_unlock() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        let kp = generate(dir.path(), &v).unwrap();
        v.lock();
        // No unlock: the public key must still be readable.
        let pub_loaded = load_public_key(dir.path()).unwrap();
        assert_eq!(kp.verifying_key().to_bytes(), pub_loaded.to_bytes());
    }

    #[test]
    fn load_signing_key_fails_when_locked() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        generate(dir.path(), &v).unwrap();
        v.lock();
        let r = load_signing_key_impl(dir.path(), &v);
        assert!(r.is_err(), "decrypting the seed must require unlock");
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        let first = load_or_generate(dir.path(), &v).unwrap();
        let second = load_or_generate(dir.path(), &v).unwrap();
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "load_or_generate must not regenerate when a key exists"
        );
    }

    #[test]
    fn rotate_generates_a_new_key() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        let first = generate(dir.path(), &v).unwrap();
        let rotated = generate(dir.path(), &v).unwrap();
        assert_ne!(
            first.to_bytes(),
            rotated.to_bytes(),
            "rotate must produce a fresh key"
        );
    }

    #[test]
    fn tampered_sealed_seed_fails_to_open() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        generate(dir.path(), &v).unwrap();
        // Flip a byte in the sealed seed.
        let path = private_key_path(dir.path());
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        let r = load_signing_key_impl(dir.path(), &v);
        assert!(r.is_err(), "GCM tag must catch a tampered seed");
    }

    #[test]
    fn parse_public_key_b64_roundtrips() {
        let dir = tempdir().unwrap();
        let v = unlocked_vault(dir.path());
        let kp = generate(dir.path(), &v).unwrap();
        let raw = std::fs::read_to_string(public_key_path(dir.path())).unwrap();
        let parsed = parse_public_key_b64(&raw).unwrap();
        assert_eq!(kp.verifying_key().to_bytes(), parsed.to_bytes());
    }
}
