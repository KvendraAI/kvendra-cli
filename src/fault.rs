//! Fault injection for crash-consistency tests (REQ-KVD-CLI-CFB449 AC-REC-5).
//!
//! Only with the cargo feature `test-hooks` (never in `default`, never in a
//! published build):
//! - `KVENDRA_TEST_FAIL_AT=<step>` → [`maybe_fail`] returns an error at that
//!   step, so the caller's rollback path runs;
//! - `KVENDRA_TEST_CRASH_AT=<step>` → the process exits immediately at that
//!   step (no destructors, no rollback): models a crash / power loss.
//!
//! Unit tests can also arm a step for the current thread with [`arm`].
//! Without the feature, [`maybe_fail`] is an inlined no-op and both env vars
//! are ignored.

use crate::error::KvendraResult;

#[cfg(feature = "test-hooks")]
thread_local! {
    static ARMED: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Exit code used by `KVENDRA_TEST_CRASH_AT`.
pub const CRASH_EXIT_CODE: i32 = 86;

/// Fail (or crash) here if this step is armed.
#[cfg(feature = "test-hooks")]
pub fn maybe_fail(step: &str) -> KvendraResult<()> {
    if std::env::var("KVENDRA_TEST_CRASH_AT").is_ok_and(|s| s == step) {
        std::process::exit(CRASH_EXIT_CODE);
    }
    let armed = ARMED.with(|a| a.borrow().as_deref() == Some(step));
    if armed || std::env::var("KVENDRA_TEST_FAIL_AT").is_ok_and(|s| s == step) {
        return Err(crate::error::KvendraError::Vault(format!(
            "injected failure at {step}"
        )));
    }
    Ok(())
}

/// No-op without the `test-hooks` feature.
#[cfg(not(feature = "test-hooks"))]
#[inline(always)]
pub fn maybe_fail(_step: &str) -> KvendraResult<()> {
    Ok(())
}

/// Arm `step` for the current thread until the guard drops.
#[cfg(feature = "test-hooks")]
pub fn arm(step: &str) -> ArmGuard {
    ARMED.with(|a| *a.borrow_mut() = Some(step.to_string()));
    ArmGuard
}

/// Disarms on drop.
#[cfg(feature = "test-hooks")]
pub struct ArmGuard;

#[cfg(feature = "test-hooks")]
impl Drop for ArmGuard {
    fn drop(&mut self) {
        ARMED.with(|a| *a.borrow_mut() = None);
    }
}
