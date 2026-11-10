//! Envelope key hierarchy (ADR-KVD-CLI-4810AF, REQ-KVD-CLI-CFB449).
//!
//! The vault key (MK) is 32 random bytes. It is never derived from the
//! password; it is WRAPPED twice:
//!
//! - `sentinel.blob` v2 — wrapped under `KEK_pw = Argon2id(password, kdf)`.
//!   Also carries `check`, an AEAD of a constant under MK, so a candidate MK
//!   (from a session blob or from the recovery phrase) can be verified
//!   without the password.
//! - `recovery.blob` v1 — wrapped under
//!   `KEK_rec = HKDF-SHA256(salt = vault_id, IKM = BIP-39 seed(""), info)`.
//!
//! Changing the password re-wraps MK (new salt, new nonces, same vault_id);
//! every HKDF sub-key, secret blob, signed allowlist/config and the audit
//! chain keep working because they all hang from MK.
//!
//! Every AEAD carries an AAD that binds the format label, the format version
//! and the `vault_id` (and, for the password wrap, the Argon2id parameters),
//! so no ciphertext can be lifted from one vault/format into another.
//!
//! Nothing here implements `Debug`/`Display` over secret bytes.

use crate::error::{KvendraError, KvendraResult, PhraseInvalidReason};
use crate::vault::blob::Blob;
use crate::vault::crypto::{NONCE_LEN, random_nonce};
use crate::vault::kdf::{KdfParams, derive};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of the vault key.
pub const MK_LEN: usize = 32;
/// Length of the public vault identifier.
pub const VAULT_ID_LEN: usize = 16;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;
/// Salt length for the v2 password wrap.
const SALT_LEN: usize = 16;

/// `sentinel.blob` format version written by this release.
pub const SENTINEL_VERSION_V2: u32 = 2;
/// Legacy 0.8.0 format (MK = Argon2id output).
pub const SENTINEL_VERSION_V1: u32 = 1;
const SENTINEL_V1_PLAINTEXT: &[u8] = b"kvendra-sentinel-v1";
const WRAP_AAD_LABEL: &[u8] = b"kvendra/sentinel-wrap/v2";
const CHECK_AAD_LABEL: &[u8] = b"kvendra/mk-check/v2";
const CHECK_PLAINTEXT: &[u8] = b"kvendra-sentinel-v2";

/// `recovery.blob` identifiers.
pub const RECOVERY_FORMAT: &str = "kvendra-recovery";
pub const RECOVERY_VERSION: u32 = 1;
pub const RECOVERY_KDF_LABEL: &str = "bip39-seed-empty-passphrase+hkdf-sha256";
pub const RECOVERY_HKDF_INFO: &[u8] = b"kvendra/recovery-wrap/v1";
const RECOVERY_AAD_LABEL: &[u8] = b"kvendra-recovery";

/// Number of words of the phrase `kvendra init` generates (128-bit entropy).
pub const RECOVERY_WORD_COUNT: usize = 12;

/// Bounds accepted for the Argon2id parameters of a v2 sentinel. A file with
/// values outside them is refused before deriving anything (a hostile
/// `m_cost_kib` would otherwise be a memory-exhaustion lever).
const MIN_M_COST_KIB: u32 = 8 * 1024;
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 8;

/// The vault key. Random, zeroized on drop, never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MK_LEN]);

impl MasterKey {
    /// Fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut k = [0u8; MK_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Wrap existing key bytes (v1 vaults, session blob). The caller keeps
    /// responsibility for wiping its own copy.
    pub fn from_bytes(bytes: [u8; MK_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; MK_LEN] {
        &self.0
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &MasterKey) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Public 16-byte vault identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VaultId(pub [u8; VAULT_ID_LEN]);

impl VaultId {
    pub fn generate() -> Self {
        let mut id = [0u8; VAULT_ID_LEN];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }

    fn from_slice(bytes: &[u8]) -> KvendraResult<Self> {
        let arr: [u8; VAULT_ID_LEN] = bytes
            .try_into()
            .map_err(|_| KvendraError::Vault("vault_id length invalid".into()))?;
        Ok(Self(arr))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VaultId({})", hex::encode(self.0))
    }
}

/// Argon2id parameters of the v2 password wrap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfV2 {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64_bytes")]
    pub salt: Vec<u8>,
}

impl KdfV2 {
    fn to_params(&self) -> KdfParams {
        KdfParams {
            m_cost_kib: self.m_cost_kib,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            salt: self.salt.clone(),
        }
    }

    fn from_params(p: &KdfParams) -> Self {
        Self {
            m_cost_kib: p.m_cost_kib,
            t_cost: p.t_cost,
            p_cost: p.p_cost,
            salt: p.salt.clone(),
        }
    }
}

/// One AEAD output: nonce + ciphertext (tag appended).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedBox {
    #[serde(with = "b64_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64_bytes")]
    pub ciphertext: Vec<u8>,
}

/// `sentinel.blob` version 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SentinelV2 {
    pub version: u32,
    #[serde(with = "b64_bytes")]
    pub vault_id: Vec<u8>,
    pub kdf: KdfV2,
    pub wrap: SealedBox,
    pub check: SealedBox,
}

/// `recovery.blob` version 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBlobV1 {
    pub format: String,
    pub version: u32,
    #[serde(with = "b64_bytes")]
    pub vault_id: Vec<u8>,
    pub kdf: String,
    #[serde(with = "b64_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Parsed `sentinel.blob`, dispatched on its `version` field.
#[derive(Debug)]
pub enum Sentinel {
    /// 0.8.0 layout: MK = Argon2id(password); constant sealed under it.
    V1(Blob),
    V2(SentinelV2),
}

/// Everything `kvendra init` needs, built in memory before any disk write.
pub struct NewVaultMaterial {
    pub master_key: MasterKey,
    pub vault_id: VaultId,
    pub sentinel: SentinelV2,
    pub recovery: RecoveryBlobV1,
    pub mnemonic: Mnemonic,
}

impl std::fmt::Debug for NewVaultMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewVaultMaterial")
            .field("master_key", &self.master_key)
            .field("vault_id", &self.vault_id)
            .field("mnemonic", &"<redacted>")
            .finish_non_exhaustive()
    }
}

// ─── AEAD helpers ────────────────────────────────────────────────────────

fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> KvendraResult<SealedBox> {
    let nonce = random_nonce();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KvendraError::Vault(format!("aes-gcm key: {e}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad })
        .map_err(|_| KvendraError::Vault("encryption failed".into()))?;
    Ok(SealedBox {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// `None` = tag did not verify (wrong key, wrong AAD or tampered bytes).
fn open(key: &[u8; 32], aad: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

fn mk_from_plaintext(pt: &[u8]) -> Option<MasterKey> {
    let arr: [u8; MK_LEN] = pt.try_into().ok()?;
    Some(MasterKey(arr))
}

// ─── AADs ────────────────────────────────────────────────────────────────

fn wrap_aad(vault_id: &[u8], kdf: &KdfV2) -> Vec<u8> {
    let mut a = Vec::with_capacity(WRAP_AAD_LABEL.len() + 1 + 16 + 12 + kdf.salt.len());
    a.extend_from_slice(WRAP_AAD_LABEL);
    a.push(0x00);
    a.extend_from_slice(vault_id);
    a.extend_from_slice(&kdf.m_cost_kib.to_be_bytes());
    a.extend_from_slice(&kdf.t_cost.to_be_bytes());
    a.extend_from_slice(&kdf.p_cost.to_be_bytes());
    a.extend_from_slice(&kdf.salt);
    a
}

fn check_aad(vault_id: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(CHECK_AAD_LABEL.len() + 1 + 16);
    a.extend_from_slice(CHECK_AAD_LABEL);
    a.push(0x00);
    a.extend_from_slice(vault_id);
    a
}

fn recovery_aad(vault_id: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(RECOVERY_AAD_LABEL.len() + 1 + 4 + 16);
    a.extend_from_slice(RECOVERY_AAD_LABEL);
    a.push(0x00);
    a.extend_from_slice(&RECOVERY_VERSION.to_be_bytes());
    a.extend_from_slice(vault_id);
    a
}

// ─── sentinel ────────────────────────────────────────────────────────────

/// Parse `sentinel.blob`: read ONLY `version` first, then the layout of that
/// version. Unknown versions fail closed.
pub fn parse_sentinel(raw: &str) -> KvendraResult<Sentinel> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| KvendraError::Vault("sentinel.blob has no format version".into()))?;
    match version {
        1 => Ok(Sentinel::V1(serde_json::from_value(value)?)),
        2 => {
            let s: SentinelV2 = serde_json::from_value(value)?;
            s.validate()?;
            Ok(Sentinel::V2(s))
        }
        other => Err(KvendraError::Vault(format!(
            "unsupported sentinel format version {other}"
        ))),
    }
}

impl Sentinel {
    pub fn version(&self) -> u32 {
        match self {
            Sentinel::V1(_) => SENTINEL_VERSION_V1,
            Sentinel::V2(_) => SENTINEL_VERSION_V2,
        }
    }

    /// Password → MK, verifying the password. Wrong password →
    /// `InvalidMasterPassword`.
    pub fn master_key_from_password(&self, password: &[u8]) -> KvendraResult<MasterKey> {
        match self {
            Sentinel::V1(blob) => {
                let derived = derive(password, &blob.kdf)?;
                if !v1_check(blob, derived.as_bytes())? {
                    return Err(KvendraError::InvalidMasterPassword);
                }
                Ok(MasterKey(*derived.as_bytes()))
            }
            Sentinel::V2(s) => s.unwrap_with_password(password),
        }
    }

    /// Whether `key` is this vault's MK (session blob / keychain path).
    pub fn verifies_master_key(&self, key: &[u8; MK_LEN]) -> KvendraResult<bool> {
        match self {
            Sentinel::V1(blob) => v1_check(blob, key),
            Sentinel::V2(s) => Ok(s.verifies(&MasterKey(*key))),
        }
    }
}

fn v1_check(blob: &Blob, key: &[u8; 32]) -> KvendraResult<bool> {
    if blob.nonce.len() != NONCE_LEN {
        return Err(KvendraError::Vault("sentinel nonce length invalid".into()));
    }
    let Some(pt) = open(key, b"", &blob.nonce, &blob.ciphertext) else {
        return Ok(false);
    };
    Ok(pt.as_slice() == SENTINEL_V1_PLAINTEXT)
}

impl SentinelV2 {
    /// Build a v2 sentinel for `mk` under `password` with `params`.
    pub fn seal(
        mk: &MasterKey,
        vault_id: VaultId,
        password: &[u8],
        params: &KdfParams,
    ) -> KvendraResult<Self> {
        let kdf = KdfV2::from_params(params);
        validate_kdf(&kdf)?;
        let kek = derive(password, params)?;
        let wrap = seal(kek.as_bytes(), &wrap_aad(&vault_id.0, &kdf), mk.as_bytes())?;
        let check = seal(mk.as_bytes(), &check_aad(&vault_id.0), CHECK_PLAINTEXT)?;
        Ok(Self {
            version: SENTINEL_VERSION_V2,
            vault_id: vault_id.0.to_vec(),
            kdf,
            wrap,
            check,
        })
    }

    pub fn vault_id(&self) -> KvendraResult<VaultId> {
        VaultId::from_slice(&self.vault_id)
    }

    /// Structural validation (lengths, version, KDF bounds).
    pub fn validate(&self) -> KvendraResult<()> {
        if self.version != SENTINEL_VERSION_V2 {
            return Err(KvendraError::Vault(format!(
                "unsupported sentinel format version {}",
                self.version
            )));
        }
        if self.vault_id.len() != VAULT_ID_LEN {
            return Err(KvendraError::Vault(
                "sentinel vault_id length invalid".into(),
            ));
        }
        validate_kdf(&self.kdf)?;
        if self.wrap.nonce.len() != NONCE_LEN || self.check.nonce.len() != NONCE_LEN {
            return Err(KvendraError::Vault("sentinel nonce length invalid".into()));
        }
        if self.wrap.ciphertext.len() != MK_LEN + TAG_LEN {
            return Err(KvendraError::Vault("sentinel wrap length invalid".into()));
        }
        if self.check.ciphertext.len() != CHECK_PLAINTEXT.len() + TAG_LEN {
            return Err(KvendraError::Vault("sentinel check length invalid".into()));
        }
        Ok(())
    }

    fn unwrap_with_password(&self, password: &[u8]) -> KvendraResult<MasterKey> {
        let kek = derive(password, &self.kdf.to_params())?;
        let pt = open(
            kek.as_bytes(),
            &wrap_aad(&self.vault_id, &self.kdf),
            &self.wrap.nonce,
            &self.wrap.ciphertext,
        )
        .ok_or(KvendraError::InvalidMasterPassword)?;
        let mk = mk_from_plaintext(&pt).ok_or(KvendraError::InvalidMasterPassword)?;
        if !self.verifies(&mk) {
            return Err(KvendraError::Vault(
                "sentinel.blob integrity check failed (wrap and check disagree)".into(),
            ));
        }
        Ok(mk)
    }

    /// Whether `mk` opens `check`.
    pub fn verifies(&self, mk: &MasterKey) -> bool {
        open(
            mk.as_bytes(),
            &check_aad(&self.vault_id),
            &self.check.nonce,
            &self.check.ciphertext,
        )
        .is_some_and(|pt| pt.as_slice() == CHECK_PLAINTEXT)
    }

    /// Re-wrap `mk` under `new_password`: fresh salt and nonces, same
    /// vault_id and same Argon2id cost parameters as `self`. `check` is
    /// re-sealed with a fresh nonce too (one nonce per write).
    pub fn rewrap(&self, mk: &MasterKey, new_password: &[u8]) -> KvendraResult<Self> {
        if !self.verifies(mk) {
            return Err(KvendraError::Vault(
                "refusing to re-wrap a key that is not this vault's".into(),
            ));
        }
        let params = KdfParams {
            m_cost_kib: self.kdf.m_cost_kib,
            t_cost: self.kdf.t_cost,
            p_cost: self.kdf.p_cost,
            salt: crate::vault::kdf::random_salt(),
        };
        Self::seal(mk, self.vault_id()?, new_password, &params)
    }

    pub fn to_json(&self) -> KvendraResult<String> {
        serde_json::to_string_pretty(self).map_err(KvendraError::from)
    }
}

fn validate_kdf(kdf: &KdfV2) -> KvendraResult<()> {
    if kdf.salt.len() != SALT_LEN {
        return Err(KvendraError::Vault("sentinel salt length invalid".into()));
    }
    if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&kdf.m_cost_kib)
        || !(1..=MAX_T_COST).contains(&kdf.t_cost)
        || !(1..=MAX_P_COST).contains(&kdf.p_cost)
    {
        return Err(KvendraError::Vault(
            "sentinel KDF parameters out of the accepted range".into(),
        ));
    }
    Ok(())
}

// ─── recovery ────────────────────────────────────────────────────────────

/// Generate the 12-word English phrase from 128 bits of OS entropy.
pub fn generate_mnemonic() -> KvendraResult<Mnemonic> {
    let mut entropy = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(entropy.as_mut());
    Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
        .map_err(|e| KvendraError::Vault(format!("bip39 generate: {e}")))
}

/// Normalize (lowercase, single spaces) and parse a user phrase. Never
/// echoes a word: the error only carries a position or a count.
pub fn parse_phrase(phrase: &str) -> KvendraResult<Mnemonic> {
    let normalized: Zeroizing<String> = Zeroizing::new(
        phrase
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" "),
    );
    let got = normalized.split(' ').filter(|w| !w.is_empty()).count();
    if got != RECOVERY_WORD_COUNT {
        return Err(KvendraError::RecoveryPhraseInvalid {
            reason: PhraseInvalidReason::WordCount { got },
        });
    }
    Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|e| {
        let reason = match e {
            bip39::Error::UnknownWord(i) => PhraseInvalidReason::UnknownWord { position: i + 1 },
            bip39::Error::BadWordCount(n) => PhraseInvalidReason::WordCount { got: n },
            _ => PhraseInvalidReason::Checksum,
        };
        KvendraError::RecoveryPhraseInvalid { reason }
    })
}

/// `KEK_rec = HKDF-SHA256(salt = vault_id, IKM = seed, info)`.
pub fn recovery_kek(mnemonic: &Mnemonic, vault_id: &[u8]) -> Zeroizing<[u8; 32]> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let hk = Hkdf::<Sha256>::new(Some(vault_id), seed.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(RECOVERY_HKDF_INFO, okm.as_mut())
        .expect("HKDF expand to 32 bytes always succeeds");
    okm
}

/// Parse `recovery.blob`: `format` and `version` are checked BEFORE the
/// body is interpreted or anything is derived.
pub fn parse_recovery_blob(raw: &str) -> KvendraResult<RecoveryBlobV1> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| KvendraError::RecoveryMaterialCorrupt("recovery.blob is not JSON".into()))?;
    if value.get("format").and_then(serde_json::Value::as_str) != Some(RECOVERY_FORMAT) {
        return Err(KvendraError::RecoveryMaterialCorrupt(
            "recovery.blob has an unknown format".into(),
        ));
    }
    match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(1) => {}
        Some(v) => {
            return Err(KvendraError::RecoveryMaterialCorrupt(format!(
                "unsupported recovery.blob version {v}"
            )));
        }
        None => {
            return Err(KvendraError::RecoveryMaterialCorrupt(
                "recovery.blob has no format version".into(),
            ));
        }
    }
    let blob: RecoveryBlobV1 = serde_json::from_value(value)
        .map_err(|_| KvendraError::RecoveryMaterialCorrupt("recovery.blob is malformed".into()))?;
    if blob.kdf != RECOVERY_KDF_LABEL
        || blob.vault_id.len() != VAULT_ID_LEN
        || blob.nonce.len() != NONCE_LEN
        || blob.ciphertext.len() != MK_LEN + TAG_LEN
    {
        return Err(KvendraError::RecoveryMaterialCorrupt(
            "recovery.blob is malformed".into(),
        ));
    }
    Ok(blob)
}

impl RecoveryBlobV1 {
    /// Wrap `mk` under the phrase-derived key.
    pub fn seal(mk: &MasterKey, vault_id: VaultId, mnemonic: &Mnemonic) -> KvendraResult<Self> {
        let kek = recovery_kek(mnemonic, &vault_id.0);
        let sealed = seal(&kek, &recovery_aad(&vault_id.0), mk.as_bytes())?;
        Ok(Self {
            format: RECOVERY_FORMAT.into(),
            version: RECOVERY_VERSION,
            vault_id: vault_id.0.to_vec(),
            kdf: RECOVERY_KDF_LABEL.into(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
        })
    }

    /// Open with `mnemonic` and verify the result against `sentinel`.
    ///
    /// - vault_id differs from the sentinel's → `RecoveryMaterialCorrupt`
    ///   (nothing is derived);
    /// - tag fails → `RecoveryPhraseMismatch`;
    /// - recovered key does not open `check` → `RecoveryMaterialCorrupt`.
    pub fn open(&self, sentinel: &SentinelV2, mnemonic: &Mnemonic) -> KvendraResult<MasterKey> {
        if !bool::from(self.vault_id.as_slice().ct_eq(sentinel.vault_id.as_slice())) {
            return Err(KvendraError::RecoveryMaterialCorrupt(
                "recovery.blob belongs to a different vault than sentinel.blob".into(),
            ));
        }
        let kek = recovery_kek(mnemonic, &self.vault_id);
        let pt = open(
            &kek,
            &recovery_aad(&self.vault_id),
            &self.nonce,
            &self.ciphertext,
        )
        .ok_or(KvendraError::RecoveryPhraseMismatch)?;
        let mk = mk_from_plaintext(&pt).ok_or_else(|| {
            KvendraError::RecoveryMaterialCorrupt("recovered key has a wrong length".into())
        })?;
        if !sentinel.verifies(&mk) {
            return Err(KvendraError::RecoveryMaterialCorrupt(
                "recovered key does not verify against sentinel.blob".into(),
            ));
        }
        Ok(mk)
    }

    pub fn to_json(&self) -> KvendraResult<String> {
        serde_json::to_string_pretty(self).map_err(KvendraError::from)
    }
}

/// Build a whole new v2 vault in memory (no disk writes).
pub fn create_v2_in_memory(password: &[u8], params: &KdfParams) -> KvendraResult<NewVaultMaterial> {
    let master_key = MasterKey::generate();
    let vault_id = VaultId::generate();
    let mnemonic = generate_mnemonic()?;
    let sentinel = SentinelV2::seal(&master_key, vault_id, password, params)?;
    let recovery = RecoveryBlobV1::seal(&master_key, vault_id, &mnemonic)?;
    Ok(NewVaultMaterial {
        master_key,
        vault_id,
        sentinel,
        recovery,
        mnemonic,
    })
}

mod b64_bytes {
    use super::B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Base64 of a value, used by tests and diagnostics on PUBLIC fields only.
pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![3u8; 16],
        }
    }

    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon about";

    #[test]
    fn v2_round_trip_and_wrong_password() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let s = Sentinel::V2(m.sentinel.clone());
        let mk = s.master_key_from_password(b"pw-correct-1").unwrap();
        assert!(mk.ct_eq(&m.master_key));
        assert!(m.sentinel.verifies(&mk));
        assert!(matches!(
            s.master_key_from_password(b"pw-wrong-11"),
            Err(KvendraError::InvalidMasterPassword)
        ));
        assert!(!s.verifies_master_key(&[0u8; 32]).unwrap());
    }

    #[test]
    fn sentinel_v2_json_round_trips_and_has_expected_shape() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let json = m.sentinel.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["version"], 2);
        assert!(v["kdf"]["salt"].is_string(), "salt is base64 in v2");
        let parsed = parse_sentinel(&json).unwrap();
        assert!(matches!(parsed, Sentinel::V2(ref p) if *p == m.sentinel));
    }

    /// AC-REC-8 — unknown versions fail closed before deriving anything
    /// (the m_cost here would take seconds if Argon2 ran).
    #[test]
    fn unknown_sentinel_version_fails_closed() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let mut v: serde_json::Value =
            serde_json::from_str(&m.sentinel.to_json().unwrap()).unwrap();
        v["version"] = 3.into();
        let err = parse_sentinel(&v.to_string()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported sentinel format version 3")
        );
        v["version"] = 2.into();
        v["kdf"]["m_cost_kib"] = (4u64 * 1024 * 1024).into();
        assert!(parse_sentinel(&v.to_string()).is_err());
        let no_version = r#"{"kdf":{}}"#;
        assert!(parse_sentinel(no_version).is_err());
    }

    /// AC-REC-8 — recovery.blob with another version / format is refused.
    #[test]
    fn unknown_recovery_format_or_version_fails_closed() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let mut v: serde_json::Value =
            serde_json::from_str(&m.recovery.to_json().unwrap()).unwrap();
        v["version"] = 2.into();
        assert!(matches!(
            parse_recovery_blob(&v.to_string()),
            Err(KvendraError::RecoveryMaterialCorrupt(ref s)) if s.contains("version 2")
        ));
        v["version"] = 1.into();
        v["format"] = "other".into();
        assert!(matches!(
            parse_recovery_blob(&v.to_string()),
            Err(KvendraError::RecoveryMaterialCorrupt(_))
        ));
        v["format"] = RECOVERY_FORMAT.into();
        v["kdf"] = "pbkdf2".into();
        assert!(parse_recovery_blob(&v.to_string()).is_err());
        v["kdf"] = RECOVERY_KDF_LABEL.into();
        assert!(parse_recovery_blob(&v.to_string()).is_ok());
    }

    #[test]
    fn recovery_round_trip() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let phrase = m.mnemonic.to_string();
        let parsed = parse_phrase(&phrase.to_uppercase().replace(' ', "   ")).unwrap();
        let blob = parse_recovery_blob(&m.recovery.to_json().unwrap()).unwrap();
        let mk = blob.open(&m.sentinel, &parsed).unwrap();
        assert!(mk.ct_eq(&m.master_key));
    }

    /// AC-REC-2 — phrase of another vault, recovery.blob of another vault,
    /// and a forged vault_id.
    #[test]
    fn foreign_phrase_foreign_blob_and_forged_vault_id() {
        let a = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let b = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        assert!(matches!(
            a.recovery.open(&a.sentinel, &b.mnemonic),
            Err(KvendraError::RecoveryPhraseMismatch)
        ));
        assert!(matches!(
            b.recovery.open(&a.sentinel, &b.mnemonic),
            Err(KvendraError::RecoveryMaterialCorrupt(_))
        ));
        // Forge the vault_id on both files so the equality check passes: the
        // AAD (and the HKDF salt) no longer match → tag fails.
        let mut forged_blob = a.recovery.clone();
        let mut forged_sentinel = a.sentinel.clone();
        forged_blob.vault_id = vec![0x42; 16];
        forged_sentinel.vault_id = vec![0x42; 16];
        assert!(matches!(
            forged_blob.open(&forged_sentinel, &a.mnemonic),
            Err(KvendraError::RecoveryPhraseMismatch)
        ));
    }

    /// AC-REC-3 — every malformed-phrase shape maps to its own reason.
    #[test]
    fn malformed_phrases_have_specific_reasons() {
        let unknown = ZERO_PHRASE.replacen("abandon", "kvdnotaword", 1);
        let eleven = ZERO_PHRASE.replacen("abandon ", "", 1);
        let thirteen = format!("abandon {ZERO_PHRASE}");
        let bad_checksum = ZERO_PHRASE.replace("about", "abandon");
        let cases = [
            (
                unknown.as_str(),
                PhraseInvalidReason::UnknownWord { position: 1 },
            ),
            (eleven.as_str(), PhraseInvalidReason::WordCount { got: 11 }),
            (
                thirteen.as_str(),
                PhraseInvalidReason::WordCount { got: 13 },
            ),
            (bad_checksum.as_str(), PhraseInvalidReason::Checksum),
        ];
        for (phrase, expected) in cases {
            match parse_phrase(phrase) {
                Err(KvendraError::RecoveryPhraseInvalid { reason }) => {
                    assert_eq!(reason, expected, "{phrase}");
                    let msg = KvendraError::RecoveryPhraseInvalid { reason }.to_string();
                    assert!(msg.contains("not a valid BIP-39"), "{msg}");
                    assert!(!msg.contains("kvdnotaword"), "error echoes the word: {msg}");
                }
                other => panic!("{phrase}: {other:?}"),
            }
        }
        assert!(parse_phrase(ZERO_PHRASE).is_ok());
    }

    #[test]
    fn rewrap_changes_wrap_and_nonces_but_not_recovery() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let s1 = m.sentinel.rewrap(&m.master_key, b"pw-new-0001").unwrap();
        let s2 = s1.rewrap(&m.master_key, b"pw-new-0002").unwrap();
        assert_ne!(s1.wrap.nonce, s2.wrap.nonce);
        assert_ne!(s1.check.nonce, s2.check.nonce);
        assert_ne!(s1.wrap.ciphertext, s2.wrap.ciphertext);
        assert_ne!(s1.kdf.salt, s2.kdf.salt);
        assert_eq!(s1.vault_id, s2.vault_id);
        assert_eq!(s1.kdf.m_cost_kib, m.sentinel.kdf.m_cost_kib);
        // recovery.blob is untouched by a password change and still opens.
        let mk = m.recovery.open(&s2, &m.mnemonic).unwrap();
        assert!(mk.ct_eq(&m.master_key));
        let s2w = Sentinel::V2(s2);
        assert!(s2w.master_key_from_password(b"pw-new-0002").is_ok());
        assert!(matches!(
            s2w.master_key_from_password(b"pw-correct-1"),
            Err(KvendraError::InvalidMasterPassword)
        ));
        // Refuses to wrap a key that is not this vault's.
        assert!(
            m.sentinel
                .rewrap(&MasterKey::generate(), b"x-y-z-123")
                .is_err()
        );
    }

    /// Frozen vector: BIP-39 all-zero phrase + vault_id 00..0f. Cross-checked
    /// with an independent PBKDF2-HMAC-SHA512 + RFC 5869 implementation.
    #[test]
    fn recovery_kek_fixed_vector() {
        let m = parse_phrase(ZERO_PHRASE).unwrap();
        let vault_id: Vec<u8> = (0u8..16).collect();
        let kek = recovery_kek(&m, &vault_id);
        assert_eq!(hex::encode(kek.as_ref()), RECOVERY_KEK_VECTOR_HEX);
        // BIP-39 reference seed for this phrase with empty passphrase.
        assert_eq!(
            hex::encode(m.to_seed_normalized("")),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    const RECOVERY_KEK_VECTOR_HEX: &str =
        "141737ba98bec470e05cf7f73ffc989772a236078fdba91e1abef7aaa423ef71";

    #[test]
    fn debug_output_never_contains_secret_material() {
        let m = create_v2_in_memory(b"pw-correct-1", &fast_params()).unwrap();
        let phrase = m.mnemonic.to_string();
        let mk_hex = hex::encode(m.master_key.as_bytes());
        let mk_b64 = B64.encode(m.master_key.as_bytes());
        let dbg = format!("{m:?} {:?}", m.master_key);
        assert!(!dbg.contains(&phrase), "{dbg}");
        let words: Vec<&str> = phrase.split(' ').collect();
        for pair in words.windows(2) {
            assert!(!dbg.contains(&pair.join(" ")), "{dbg}");
        }
        assert!(!dbg.contains(&mk_hex) && !dbg.contains(&mk_b64));
        let kek = recovery_kek(&m.mnemonic, &m.vault_id.0);
        assert!(!dbg.contains(&hex::encode(kek.as_ref())));
    }
}
