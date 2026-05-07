//! Biometric / OS-presence approval backend (REQ-KVD-006 / ISSUE-KVD-CLI-020).
//!
//! Used when `ServerContext.transport == Transport::Mcp` and the resolved
//! mode is `Ask` or `AskDestructive`. Delegates to
//! [`crate::keychain_acl::request_user_presence_only`], which on macOS shows
//! an OS-modal popup (osascript dialog in this release; TouchID-native
//! `LAContext.evaluatePolicy` is a future hardening). The prompt never
//! touches `/dev/tty`, mitigating PAT-KVD-007.
//!
//! On Windows / Linux the underlying `keychain_acl` returns `Unavailable`
//! and the decision becomes `ApprovalDecision::BiometricUnavailable`.

use crate::approval::{ApprovalBackend, ApprovalContext, ApprovalDecision};
use crate::keychain_acl::{self, BiometricError};

pub struct BiometricApprovalBackend;

impl ApprovalBackend for BiometricApprovalBackend {
    fn ask(
        &self,
        ctx: ApprovalContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ApprovalDecision> + Send + '_>> {
        Box::pin(async move {
            let reason = build_reason(&ctx);
            // The OS popup is synchronous (osascript spawn / future LAContext
            // call). Run it on a blocking thread to avoid stalling the
            // tokio reactor.
            tokio::task::spawn_blocking(move || {
                match keychain_acl::request_user_presence_only(&reason) {
                    Ok(()) => ApprovalDecision::BiometricGranted,
                    Err(BiometricError::Rejected) => ApprovalDecision::BiometricRejected,
                    Err(BiometricError::Unavailable(_)) => ApprovalDecision::BiometricUnavailable,
                    // NotFound / Backend → degrade to Unavailable: the broker
                    // cannot prove user presence, so fail-safe.
                    Err(_) => ApprovalDecision::BiometricUnavailable,
                }
            })
            .await
            .unwrap_or(ApprovalDecision::BiometricUnavailable)
        })
    }
}

fn build_reason(ctx: &ApprovalContext) -> String {
    let kind = if ctx.destructive {
        "Destructive"
    } else {
        "Operation"
    };
    if ctx.profile_id.is_empty() {
        format!("{kind}: {} ({})", ctx.primitive, ctx.operation)
    } else {
        format!(
            "{kind}: {} on profile '{}' ({})",
            ctx.primitive, ctx.profile_id, ctx.operation
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalMode;

    fn ctx(destructive: bool) -> ApprovalContext {
        ApprovalContext {
            profile_id: "p1".into(),
            primitive: "kvendra.aws".into(),
            operation: "s3_sync".into(),
            args_summary: "bucket=foo".into(),
            destructive,
            mode: ApprovalMode::AskDestructive,
            timeout_seconds: 30,
        }
    }

    #[test]
    fn build_reason_marks_destructive() {
        let r = build_reason(&ctx(true));
        assert!(r.starts_with("Destructive"), "got: {r}");
        assert!(r.contains("kvendra.aws"));
        assert!(r.contains("p1"));
        assert!(r.contains("s3_sync"));
    }

    #[test]
    fn build_reason_for_non_destructive_says_operation() {
        let r = build_reason(&ctx(false));
        assert!(r.starts_with("Operation"), "got: {r}");
    }

    #[test]
    fn build_reason_handles_empty_profile_id() {
        let mut c = ctx(true);
        c.profile_id = String::new();
        let r = build_reason(&c);
        assert!(!r.contains("profile ''"), "got: {r}");
        assert!(r.contains("kvendra.aws"));
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn non_macos_returns_biometric_unavailable() {
        // On Linux / Windows the keychain_acl::other stub returns Unavailable.
        // The backend must surface that as BiometricUnavailable (not panic, not
        // BiometricGranted by accident).
        let backend = BiometricApprovalBackend;
        let decision = backend.ask(ctx(true)).await;
        assert_eq!(decision, ApprovalDecision::BiometricUnavailable);
    }
}
