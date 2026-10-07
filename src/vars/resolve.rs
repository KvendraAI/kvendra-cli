//! Substitution step of the broker (REQ-KVD-11F906 D3/D4/D6, RF-CLI-3/4).
//!
//! `prepare` walks the `tools/call` arguments and replaces every UNESCAPED
//! `{{lvr:key}}` by its stored value, recording a [`LvrSite`] per
//! substitution. The allowlist is then evaluated on the RESOLVED arguments
//! and [`super::position::check`] refuses any site outside a bounded field.
//! Audit, args hash, detection and the resolver's call context keep using the
//! ORIGINAL arguments (with references).
//!
//! Refusals happen BEFORE anything executes: locked vault, undefined,
//! unverified or invalid variable, rate limit, and an unescaped
//! `{{cfg:…}}` in a bounded position (the broker never resolves cfg).
//! Escaped references (`\{{lvr:k}}`) pass through literally, backslash
//! included — never substituted, never unescaped.

use super::filter::KnownValues;
use super::rate::RateLimiter;
use super::refs::{Ns, find_all, may_contain_ref};
use super::validate::{final_path_is_canonical, validate};
use super::{LvrError, VarType, VarsDoc};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// One substitution: where (JSON pointer into the arguments), which key and
/// its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvrSite {
    pub pointer: String,
    pub key: String,
    pub var_type: VarType,
}

/// Output of [`prepare`].
#[derive(Debug, Clone)]
pub struct Prepared {
    pub resolved: Value,
    pub sites: Vec<LvrSite>,
    pub keys: BTreeSet<String>,
}

impl Prepared {
    fn passthrough(args: &Value) -> Self {
        Self {
            resolved: args.clone(),
            sites: Vec::new(),
            keys: BTreeSet::new(),
        }
    }
}

struct CacheEntry {
    mtime: Option<SystemTime>,
    len: u64,
    doc: Arc<VarsDoc>,
    known: Arc<KnownValues>,
}

/// Broker-side local-vars state, one per `ServerContext`: the decrypted
/// `vars.blob` cache (RAM only, values zeroized on drop, reloaded when the
/// file's mtime/size changes, dropped when the vault locks) and the per-key
/// rate limiter.
#[derive(Default)]
pub struct LvrState {
    cache: Mutex<Option<CacheEntry>>,
    pub rate: RateLimiter,
}

impl LvrState {
    /// Current document + maskable values. `Ok(None)` when there is no
    /// `vars.blob`; `Err(VaultLocked)` when the vault is locked (the cache is
    /// dropped then).
    #[allow(clippy::type_complexity)]
    pub fn snapshot(
        &self,
        vault: &Vault,
    ) -> KvendraResult<Option<(Arc<VarsDoc>, Arc<KnownValues>)>> {
        let mut guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if !vault.is_unlocked() {
            *guard = None;
            return Err(KvendraError::VaultLocked);
        }
        let path = vault.vars_blob_path();
        let Ok(meta) = std::fs::metadata(&path) else {
            *guard = None;
            return Ok(None);
        };
        let mtime = meta.modified().ok();
        if let Some(c) = guard.as_ref()
            && c.mtime == mtime
            && c.len == meta.len()
        {
            return Ok(Some((c.doc.clone(), c.known.clone())));
        }
        let doc = Arc::new(super::load(vault)?);
        let known = Arc::new(KnownValues::from_doc(&doc));
        *guard = Some(CacheEntry {
            mtime,
            len: meta.len(),
            doc: doc.clone(),
            known: known.clone(),
        });
        Ok(Some((doc, known)))
    }

    /// Best-effort maskable values (None when locked / no vars / unreadable).
    pub fn known_values(&self, vault: &Vault) -> Option<Arc<KnownValues>> {
        match self.snapshot(vault) {
            Ok(Some((_, k))) if !k.is_empty() => Some(k),
            _ => None,
        }
    }
}

/// Fields whose final value a signed constraint can bound (D3). An unescaped
/// `{{cfg:…}}` here is refused (`cfg_ref_not_resolvable_by_broker`).
pub fn is_bounded_pointer(pointer: &str) -> bool {
    matches!(
        pointer,
        "/profile_id" | "/args/cwd" | "/args/url" | "/args/src" | "/args/dst" | "/args/dist"
    ) || argv_index(pointer).is_some()
}

/// `Some(i)` for `/args/argv/<i>`.
pub fn argv_index(pointer: &str) -> Option<usize> {
    pointer.strip_prefix("/args/argv/")?.parse().ok()
}

/// Path-carrying fields whose FINAL value is re-checked for canonicity when
/// a `path` variable was substituted into them.
fn is_path_field(pointer: &str) -> bool {
    matches!(
        pointer,
        "/args/cwd" | "/args/src" | "/args/dst" | "/args/dist"
    )
}

fn escape_token(t: &str) -> String {
    t.replace('~', "~0").replace('/', "~1")
}

/// Fast check: does `args` mention any reference at all?
pub fn mentions_refs(args: &Value) -> bool {
    match args {
        Value::String(s) => may_contain_ref(s),
        Value::Array(a) => a.iter().any(mentions_refs),
        Value::Object(m) => m.values().any(mentions_refs),
        _ => false,
    }
}

/// Resolve the references of `args`. See the module doc.
pub fn prepare(state: &LvrState, vault: &Vault, args: &Value) -> Result<Prepared, LvrError> {
    // Fast path: no reference → current behaviour, the vault is not touched.
    if !mentions_refs(args) {
        return Ok(Prepared::passthrough(args));
    }
    let mut out = Prepared::passthrough(args);
    let mut doc: Option<Arc<VarsDoc>> = None;
    walk(
        state,
        vault,
        &mut out.resolved,
        String::new(),
        &mut doc,
        &mut out.sites,
    )?;
    out.keys = out.sites.iter().map(|s| s.key.clone()).collect();
    Ok(out)
}

fn walk(
    state: &LvrState,
    vault: &Vault,
    v: &mut Value,
    pointer: String,
    doc: &mut Option<Arc<VarsDoc>>,
    sites: &mut Vec<LvrSite>,
) -> Result<(), LvrError> {
    match v {
        Value::String(s) => {
            if let Some(new) = substitute(state, vault, s, &pointer, doc, sites)? {
                *s = new;
            }
            Ok(())
        }
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                walk(state, vault, x, format!("{pointer}/{i}"), doc, sites)?;
            }
            Ok(())
        }
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                walk(
                    state,
                    vault,
                    x,
                    format!("{pointer}/{}", escape_token(k)),
                    doc,
                    sites,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn substitute(
    state: &LvrState,
    vault: &Vault,
    s: &str,
    pointer: &str,
    doc: &mut Option<Arc<VarsDoc>>,
    sites: &mut Vec<LvrSite>,
) -> Result<Option<String>, LvrError> {
    if !may_contain_ref(s) {
        return Ok(None);
    }
    let hits: Vec<_> = find_all(s).into_iter().filter(|h| !h.escaped).collect();
    if hits.is_empty() {
        return Ok(None);
    }
    if let Some(h) = hits.iter().find(|h| h.ns == Ns::Cfg)
        && is_bounded_pointer(pointer)
    {
        return Err(LvrError::new(
            "cfg_ref_not_resolvable_by_broker",
            h.key.clone(),
        ));
    }
    let lvr_hits: Vec<_> = hits.into_iter().filter(|h| h.ns == Ns::Lvr).collect();
    if lvr_hits.is_empty() {
        return Ok(None);
    }
    // Lazily load the store on the first real reference (RF-CLI-4: no
    // fallback when the vault is locked).
    if doc.is_none() {
        let loaded = match state.snapshot(vault) {
            Ok(Some((d, _))) => d,
            Ok(None) => Arc::new(VarsDoc::default()),
            Err(KvendraError::VaultLocked) => {
                return Err(LvrError::new("lvr_vault_locked", lvr_hits[0].key.clone()));
            }
            Err(_) => return Err(LvrError::new("lvr_undefined", lvr_hits[0].key.clone())),
        };
        *doc = Some(loaded);
    }
    let d = doc.as_ref().expect("loaded above");

    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut path_substituted = false;
    for h in &lvr_hits {
        let var = d
            .vars
            .get(&h.key)
            .ok_or_else(|| LvrError::new("lvr_undefined", h.key.clone()))?;
        if !var.verified {
            return Err(LvrError::new("lvr_unverified", h.key.clone()));
        }
        let value =
            validate(var.var_type, &var.value).map_err(|c| LvrError::new(c, h.key.clone()))?;
        if var.var_type == VarType::ProfileId {
            let in_vault = vault
                .checked_profile_blob_path(&value)
                .is_ok_and(|p| p.exists());
            if !in_vault {
                return Err(LvrError::new("lvr_profile_not_in_vault", h.key.clone()));
            }
        }
        if !state.rate.try_take(&h.key) {
            return Err(LvrError::new("lvr_rate_limited", h.key.clone()));
        }
        path_substituted |= var.var_type == VarType::Path;
        out.push_str(&s[last..h.start]);
        out.push_str(&value);
        last = h.end;
        sites.push(LvrSite {
            pointer: pointer.to_string(),
            key: h.key.clone(),
            var_type: var.var_type,
        });
    }
    out.push_str(&s[last..]);
    if path_substituted
        && is_path_field(pointer)
        && !out.starts_with("s3://")
        && !final_path_is_canonical(&out)
    {
        return Err(LvrError::new(
            "lvr_path_not_canonical",
            lvr_hits[0].key.clone(),
        ));
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointers() {
        assert!(is_bounded_pointer("/args/argv/3"));
        assert!(is_bounded_pointer("/profile_id"));
        assert!(!is_bounded_pointer("/args/message"));
        assert!(!is_bounded_pointer("/args/argv/x"));
        assert_eq!(argv_index("/args/argv/12"), Some(12));
        assert_eq!(escape_token("a/b~c"), "a~1b~0c");
    }

    #[test]
    fn no_refs_is_passthrough_without_vault() {
        let state = LvrState::default();
        let vault = Vault::new(std::path::PathBuf::from("/nonexistent-kvd-sentinel"));
        let args = serde_json::json!({"args": {"cwd": "/x", "m": "\\{{lvr:k}}"}});
        // Only an escaped reference → still no vault access needed? The fast
        // check sees `{{lvr:` so it walks, but the escaped hit is skipped.
        let p = prepare(&state, &vault, &args).unwrap();
        assert_eq!(p.resolved, args);
        assert!(p.sites.is_empty());
    }

    #[test]
    fn locked_vault_refuses() {
        let state = LvrState::default();
        let vault = Vault::new(std::path::PathBuf::from("/nonexistent-kvd-sentinel"));
        let args = serde_json::json!({"args": {"cwd": "{{lvr:ws}}"}});
        let e = prepare(&state, &vault, &args).unwrap_err();
        assert_eq!(e.code, "lvr_vault_locked");
        assert_eq!(e.key, "ws");
    }

    #[test]
    fn cfg_in_bounded_position_refused_but_literal_elsewhere() {
        let state = LvrState::default();
        let vault = Vault::new(std::path::PathBuf::from("/nonexistent-kvd-sentinel"));
        let e = prepare(
            &state,
            &vault,
            &serde_json::json!({"args": {"cwd": "{{cfg:home}}"}}),
        )
        .unwrap_err();
        assert_eq!(e.code, "cfg_ref_not_resolvable_by_broker");
        let ok = prepare(
            &state,
            &vault,
            &serde_json::json!({"args": {"message": "see {{cfg:home}}"}}),
        )
        .unwrap();
        assert!(ok.sites.is_empty());
    }
}
