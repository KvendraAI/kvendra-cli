//! macOS implementation of presence-gated keychain access
//! (REQ-KVD-005 / ISSUE-KVD-CLI-017).
//!
//! Stores a generic password under `service: kvendra` with
//! `kSecAttrAccessControl = SecAccessControl(.userPresence)`. Every read
//! triggers the OS-managed TouchID popup (or the modal password popup
//! when biometric hardware is absent).
//!
//! `core-foundation` + `security-framework` are used directly because
//! the high-level `keyring` crate does not expose access-control attributes.

use super::{BiometricError, KEYCHAIN_SERVICE};
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef};
use core_foundation_sys::data::CFDataGetTypeID;
use security_framework::access_control::SecAccessControl;
use security_framework_sys::base::{errSecAuthFailed, errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

/// macOS error code for "user explicitly cancelled the auth prompt".
/// Apple's value (defined in CoreServices/CarbonCore.h, not re-exported by
/// `security-framework-sys`).
const ERR_SEC_USER_CANCELED: i32 = -128;

/// `kSecAccessControlUserPresence` flag value as defined by Apple's
/// `SecAccessControl.h`. The `security-framework` crate accepts the raw
/// `CFOptionFlags` (`u64`) here.
const SEC_ACCESS_CONTROL_USER_PRESENCE: core_foundation::base::CFOptionFlags = 1;

fn build_query(label: &str) -> CFMutableDictionary<CFString, core_foundation::base::CFType> {
    let mut q = CFMutableDictionary::new();
    unsafe {
        q.add(
            &CFString::wrap_under_get_rule(kSecClass),
            &CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType(),
        );
        q.add(
            &CFString::wrap_under_get_rule(kSecAttrService),
            &CFString::new(KEYCHAIN_SERVICE).as_CFType(),
        );
        q.add(
            &CFString::wrap_under_get_rule(kSecAttrAccount),
            &CFString::new(label).as_CFType(),
        );
    }
    q
}

pub fn save_with_user_presence(label: &str, secret: &str) -> Result<(), BiometricError> {
    let access_control = SecAccessControl::create_with_flags(SEC_ACCESS_CONTROL_USER_PRESENCE)
        .map_err(|e| BiometricError::Backend(format!("create access control: {e}")))?;

    // Always delete any pre-existing item first so re-saving with a different
    // ACL or after migration produces a clean entry.
    let _ = delete(label);

    let mut query = build_query(label);
    let data = CFData::from_buffer(secret.as_bytes());
    unsafe {
        query.add(
            &CFString::wrap_under_get_rule(kSecValueData),
            &data.as_CFType(),
        );
        query.add(
            &CFString::wrap_under_get_rule(kSecAttrAccessControl),
            &access_control.as_CFType(),
        );
    }

    let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) };
    map_status_to_void(status)
}

pub fn read_with_user_presence(label: &str) -> Result<String, BiometricError> {
    let mut query = build_query(label);
    unsafe {
        let cf_true = core_foundation::boolean::CFBoolean::true_value();
        query.add(
            &CFString::wrap_under_get_rule(kSecReturnData),
            &cf_true.as_CFType(),
        );
    }

    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    map_status_to_kind(status, label)?;

    if result.is_null() {
        return Err(BiometricError::NotFound(label.to_string()));
    }
    let bytes = unsafe {
        let type_id = CFGetTypeID(result);
        if type_id != CFDataGetTypeID() {
            CFRelease(result);
            return Err(BiometricError::Backend(format!(
                "unexpected CFTypeRef returned for label={label}"
            )));
        }
        let data = CFData::wrap_under_create_rule(result as _);
        data.bytes().to_vec()
    };
    String::from_utf8(bytes)
        .map_err(|e| BiometricError::Backend(format!("keychain item not utf8: {e}")))
}

pub fn delete(label: &str) -> Result<(), BiometricError> {
    let query = build_query(label);
    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    if status == errSecItemNotFound {
        return Err(BiometricError::NotFound(label.to_string()));
    }
    map_status_to_void(status)
}

fn map_status_to_void(status: i32) -> Result<(), BiometricError> {
    match status {
        s if s == errSecSuccess => Ok(()),
        s if s == ERR_SEC_USER_CANCELED || s == errSecAuthFailed => Err(BiometricError::Rejected),
        other => Err(BiometricError::Backend(format!("OSStatus {other}"))),
    }
}

fn map_status_to_kind(status: i32, label: &str) -> Result<(), BiometricError> {
    match status {
        s if s == errSecSuccess => Ok(()),
        s if s == errSecItemNotFound => Err(BiometricError::NotFound(label.to_string())),
        s if s == ERR_SEC_USER_CANCELED || s == errSecAuthFailed => Err(BiometricError::Rejected),
        other => Err(BiometricError::Backend(format!("OSStatus {other}"))),
    }
}

/// Show an OS-modal approval popup and block until the user accepts or
/// dismisses. Used by [`crate::approval::biometric::BiometricApprovalBackend`]
/// to gate `tools/call` decisions on real human presence — without ever
/// touching `/dev/tty` (mitigates PAT-KVD-007).
///
/// Implementation detail: this release shells out to `osascript` to display
/// a native dialog (Approve / Cancel buttons). Migrating to a TouchID-native
/// `LAContext.evaluatePolicy` call is straightforward (drop-in replacement
/// at this call site) but requires ObjC FFI + block callbacks; deferred to
/// a follow-up iteration when the complexity is justified.
pub fn request_user_presence_only(reason: &str) -> Result<(), BiometricError> {
    let sanitized = sanitize_for_applescript(reason);
    let script = format!(
        "display dialog \"{sanitized}\" with title \"kvendra approval\" \
         buttons {{\"Cancel\", \"Approve\"}} default button \"Approve\" \
         cancel button \"Cancel\" with icon caution"
    );

    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| {
            BiometricError::Unavailable(format!(
                "failed to spawn osascript ({e}); is `osascript` available on PATH?"
            ))
        })?;

    if output.status.success() {
        return Ok(());
    }
    // osascript exits 1 on Cancel / on AppleScript runtime error. Both stderr
    // strings include "User canceled." for the dialog cancel path. Any other
    // failure is a backend / availability problem.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("User canceled") || stderr.contains("-128") {
        Err(BiometricError::Rejected)
    } else {
        Err(BiometricError::Backend(format!(
            "osascript failed: {}",
            stderr.trim()
        )))
    }
}

/// Escape characters that would break the AppleScript string literal we
/// embed into the `osascript -e` argument. Only `"` and `\` are special
/// inside an AppleScript double-quoted string.
fn sanitize_for_applescript(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::sanitize_for_applescript;

    #[test]
    fn sanitize_escapes_quote_and_backslash() {
        assert_eq!(sanitize_for_applescript(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn sanitize_passes_plain_text() {
        assert_eq!(
            sanitize_for_applescript("Destructive: kvendra.aws on profile 'p1' (s3_sync)"),
            "Destructive: kvendra.aws on profile 'p1' (s3_sync)"
        );
    }
}
