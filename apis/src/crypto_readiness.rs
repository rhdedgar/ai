// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Readiness from effective OpenSSL properties and supported host crypto policy.
//!
//! These checks follow host configuration. They never load a provider or change
//! the default property query, and readiness is not a certification assertion.

#[cfg(any(target_os = "linux", test))]
use std::path::Path;
use std::{fmt, io::ErrorKind};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The RHEL-family system crypto policy configuration.
const CRYPTO_POLICIES_CONFIG: &str = "/etc/crypto-policies/config";
/// The Linux kernel's FIPS mode flag.
const KERNEL_FIPS_FLAG: &str = "/proc/sys/crypto/fips_enabled";

/// A readiness observation, retaining why a prerequisite is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessSignal<T> {
    /// Successfully inspected state.
    Observed(T),
    /// The platform or library does not support this check.
    Unsupported,
    /// The prerequisite's fixed system path does not exist.
    Missing,
    /// Reading failed; no file contents are retained.
    ReadFailed(ErrorKind),
    /// Malformed or empty contents.
    Invalid,
}

/// System policy classification. Raw configuration is deliberately not retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoPolicy {
    /// The base policy is exactly `FIPS`, optionally with subpolicies.
    Fips,
    /// A valid policy with a different base.
    Other,
}

/// The three independent readiness prerequisites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoReadiness {
    /// System crypto policy, detected on Linux through crypto-policies.
    pub crypto_policy: ReadinessSignal<CryptoPolicy>,
    /// Linux kernel FIPS mode flag.
    pub kernel_fips: ReadinessSignal<bool>,
    /// Direct effective-default-property observation through the safe provider
    /// wrapper for `EVP_default_properties_is_fips_enabled(NULL)`.
    pub openssl_fips_properties: ReadinessSignal<bool>,
}

impl CryptoReadiness {
    /// Inspect the effective library state and supported host signals.
    #[must_use]
    pub fn check() -> Self {
        let openssl_fips_properties = rustls_openssl::fips::default_properties_enabled()
            .map_or(ReadinessSignal::Unsupported, ReadinessSignal::Observed);
        let (crypto_policy, kernel_fips) = system_signals();
        Self {
            crypto_policy,
            kernel_fips,
            openssl_fips_properties,
        }
    }

    /// True only when every prerequisite was observed and is positive.
    #[must_use]
    pub fn fips_ready(self) -> bool {
        self.crypto_policy == ReadinessSignal::Observed(CryptoPolicy::Fips)
            && self.kernel_fips == ReadinessSignal::Observed(true)
            && self.openssl_fips_properties == ReadinessSignal::Observed(true)
    }

    /// Every failed prerequisite, without configuration contents.
    #[must_use]
    pub fn unmet(self) -> Vec<ReadinessFailure> {
        [
            failure(
                Prerequisite::OpenSslProperties,
                self.openssl_fips_properties,
                |enabled| enabled,
            ),
            failure(Prerequisite::Kernel, self.kernel_fips, |enabled| enabled),
            failure(Prerequisite::SystemPolicy, self.crypto_policy, |policy| {
                policy == CryptoPolicy::Fips
            }),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// Whether a required check is unsupported by the platform or library.
    /// Missing files and read errors remain separate states.
    #[must_use]
    pub fn unsupported(self) -> bool {
        matches!(self.crypto_policy, ReadinessSignal::Unsupported)
            || matches!(self.kernel_fips, ReadinessSignal::Unsupported)
            || matches!(self.openssl_fips_properties, ReadinessSignal::Unsupported)
    }
}

/// A prerequisite that failed readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prerequisite {
    /// The operating system's kernel flag.
    Kernel,
    /// The effective OpenSSL default property query.
    OpenSslProperties,
    /// The system crypto policy's base selection.
    SystemPolicy,
}

/// Why a prerequisite failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureReason {
    /// Observed successfully, but not enabled or not a FIPS base policy.
    Disabled,
    /// Invalid or empty file contents.
    Invalid,
    /// Missing system path.
    Missing,
    /// System path could not be read.
    ReadFailed(ErrorKind),
    /// Unsupported platform or OpenSSL API.
    Unsupported,
}

/// An actionable failure that contains no configuration contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessFailure {
    /// Failed prerequisite.
    pub prerequisite: Prerequisite,
    /// Failed observation or negative result.
    pub reason: FailureReason,
}

impl fmt::Display for ReadinessFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, action) = match self.prerequisite {
            Prerequisite::Kernel => (
                KERNEL_FIPS_FLAG,
                "verify host FIPS setup and the container's /proc mount",
            ),
            Prerequisite::OpenSslProperties => (
                "EVP_default_properties_is_fips_enabled",
                "verify OpenSSL 3 and the host OpenSSL configuration select fips=yes",
            ),
            Prerequisite::SystemPolicy => (
                CRYPTO_POLICIES_CONFIG,
                "verify a supported crypto-policies installation selects the FIPS base policy",
            ),
        };
        let prerequisite = match self.prerequisite {
            Prerequisite::Kernel => "kernel FIPS flag",
            Prerequisite::OpenSslProperties => "OpenSSL effective default properties",
            Prerequisite::SystemPolicy => "system crypto policy",
        };
        write!(f, "{prerequisite} ({label}): ")?;
        match self.reason {
            FailureReason::Disabled => f.write_str("not enabled")?,
            FailureReason::Invalid => f.write_str("invalid or empty contents")?,
            FailureReason::Missing => f.write_str("missing")?,
            FailureReason::ReadFailed(kind) => write!(f, "read failed ({kind:?})")?,
            FailureReason::Unsupported => f.write_str("unsupported")?,
        }
        write!(f, "; {action}")
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Classify an observation without erasing its failure state.
fn failure<T>(
    prerequisite: Prerequisite,
    signal: ReadinessSignal<T>,
    positive: impl FnOnce(T) -> bool,
) -> Option<ReadinessFailure> {
    let reason = match signal {
        ReadinessSignal::Observed(value) => {
            if positive(value) {
                return None;
            }
            FailureReason::Disabled
        },
        ReadinessSignal::Unsupported => FailureReason::Unsupported,
        ReadinessSignal::Missing => FailureReason::Missing,
        ReadinessSignal::ReadFailed(kind) => FailureReason::ReadFailed(kind),
        ReadinessSignal::Invalid => FailureReason::Invalid,
    };
    Some(ReadinessFailure { prerequisite, reason })
}

/// Parse exactly one policy selection, with nonempty colon-delimited names.
/// Prefix lookalikes and another policy's FIPS subpolicy are negative.
#[cfg(any(target_os = "linux", test))]
fn crypto_policy_from(contents: &str) -> ReadinessSignal<CryptoPolicy> {
    let mut lines = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let Some(policy) = lines.next() else {
        return ReadinessSignal::Invalid;
    };
    if lines.next().is_some() {
        return ReadinessSignal::Invalid;
    }
    let mut names = policy.split(':');
    let base = names.next().unwrap_or_default();
    let valid_name = |name: &str| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    if !valid_name(base) || !names.all(valid_name) {
        return ReadinessSignal::Invalid;
    }
    ReadinessSignal::Observed(if base == "FIPS" {
        CryptoPolicy::Fips
    } else {
        CryptoPolicy::Other
    })
}

/// Parse the kernel flag strictly.
#[cfg(any(target_os = "linux", test))]
fn kernel_flag_from(contents: &str) -> ReadinessSignal<bool> {
    match contents.trim() {
        "1" => ReadinessSignal::Observed(true),
        "0" => ReadinessSignal::Observed(false),
        _ => ReadinessSignal::Invalid,
    }
}

/// Preserve filesystem failure categories, including invalid UTF-8.
#[cfg(any(target_os = "linux", test))]
fn read_signal<T>(path: &Path, parse: impl FnOnce(&str) -> ReadinessSignal<T>) -> ReadinessSignal<T> {
    signal_from_read(std::fs::read_to_string(path), parse)
}

/// Separate I/O classification from filesystem access for deterministic tests.
#[cfg(any(target_os = "linux", test))]
fn signal_from_read<T>(
    result: std::io::Result<String>,
    parse: impl FnOnce(&str) -> ReadinessSignal<T>,
) -> ReadinessSignal<T> {
    match result {
        Ok(contents) => parse(&contents),
        Err(error) => match error.kind() {
            ErrorKind::NotFound => ReadinessSignal::Missing,
            ErrorKind::InvalidData => ReadinessSignal::Invalid,
            kind => ReadinessSignal::ReadFailed(kind),
        },
    }
}

/// Platform-specific system policy detection; unsupported targets cannot pass.
fn system_signals() -> (ReadinessSignal<CryptoPolicy>, ReadinessSignal<bool>) {
    #[cfg(target_os = "linux")]
    {
        (
            read_signal(Path::new(CRYPTO_POLICIES_CONFIG), crypto_policy_from),
            read_signal(Path::new(KERNEL_FIPS_FLAG), kernel_flag_from),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        (ReadinessSignal::Unsupported, ReadinessSignal::Unsupported)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test fixture failures must stop the test")]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "table checks every failure state across all prerequisites"
    )]
    fn every_signal_is_required_and_every_failure_is_retained() {
        let ready = ready();
        assert!(ready.fips_ready(), "all positive signals pass");
        assert!(!ready.unsupported(), "all signals are supported");
        for signal in [
            ReadinessSignal::Observed(false),
            ReadinessSignal::Unsupported,
            ReadinessSignal::Missing,
            ReadinessSignal::ReadFailed(ErrorKind::PermissionDenied),
            ReadinessSignal::Invalid,
        ] {
            for observation in [
                CryptoReadiness {
                    kernel_fips: signal,
                    ..ready
                },
                CryptoReadiness {
                    openssl_fips_properties: signal,
                    ..ready
                },
            ] {
                assert!(!observation.fips_ready(), "{observation:?}");
                assert_eq!(observation.unmet().len(), 1, "{observation:?}");
                assert_eq!(
                    observation.unsupported(),
                    matches!(signal, ReadinessSignal::Unsupported)
                );
            }
        }
        for signal in [
            ReadinessSignal::Observed(CryptoPolicy::Other),
            ReadinessSignal::Unsupported,
            ReadinessSignal::Missing,
            ReadinessSignal::ReadFailed(ErrorKind::PermissionDenied),
            ReadinessSignal::Invalid,
        ] {
            let observation = CryptoReadiness {
                crypto_policy: signal,
                ..ready
            };
            assert!(!observation.fips_ready(), "{observation:?}");
            assert_eq!(observation.unmet().len(), 1, "{observation:?}");
            assert_eq!(
                observation.unsupported(),
                matches!(signal, ReadinessSignal::Unsupported)
            );
        }
        let failed = CryptoReadiness {
            crypto_policy: ReadinessSignal::Missing,
            kernel_fips: ReadinessSignal::Invalid,
            openssl_fips_properties: ReadinessSignal::Observed(false),
        };
        assert_eq!(failed.unmet().len(), 3, "all failures are reported together");
    }

    #[test]
    fn policies_require_an_exact_fips_base_and_valid_subpolicies() {
        for policy in ["FIPS", "FIPS:OSPP", "FIPS:OSPP:NO-SHA1", " # comment\n\n FIPS \n"] {
            assert_eq!(
                crypto_policy_from(policy),
                ReadinessSignal::Observed(CryptoPolicy::Fips),
                "{policy:?}"
            );
        }
        for policy in ["DEFAULT", "FIPSXYZ", "FIPS-DRAFT", "DEFAULT:FIPS", "fips"] {
            assert_eq!(
                crypto_policy_from(policy),
                ReadinessSignal::Observed(CryptoPolicy::Other),
                "{policy:?}"
            );
        }
        for policy in [
            "",
            "# comments only\n",
            "FIPS:",
            "FIPS::OSPP",
            "FIPS: OSPP",
            "FIPS\nDEFAULT",
            "FIPS#secret",
        ] {
            assert_eq!(crypto_policy_from(policy), ReadinessSignal::Invalid, "{policy:?}");
        }
    }

    #[test]
    fn file_observations_preserve_missing_invalid_and_io_failures() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy");
        assert_eq!(read_signal(&path, crypto_policy_from), ReadinessSignal::Missing);
        for (contents, expected) in [
            ("FIPS", ReadinessSignal::Observed(CryptoPolicy::Fips)),
            ("FIPS:OSPP", ReadinessSignal::Observed(CryptoPolicy::Fips)),
            ("DEFAULT", ReadinessSignal::Observed(CryptoPolicy::Other)),
            ("FIPSXYZ", ReadinessSignal::Observed(CryptoPolicy::Other)),
            ("", ReadinessSignal::Invalid),
            ("# comment", ReadinessSignal::Invalid),
        ] {
            std::fs::write(&path, contents).expect("write policy fixture");
            assert_eq!(read_signal(&path, crypto_policy_from), expected, "{contents:?}");
        }
        std::fs::write(&path, [0xFF]).expect("write invalid UTF-8");
        assert_eq!(read_signal(&path, crypto_policy_from), ReadinessSignal::Invalid);
        assert_eq!(
            signal_from_read(
                Err(std::io::Error::from(ErrorKind::PermissionDenied)),
                crypto_policy_from
            ),
            ReadinessSignal::ReadFailed(ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn kernel_values_are_strict() {
        assert_eq!(kernel_flag_from(" 1\n"), ReadinessSignal::Observed(true));
        assert_eq!(kernel_flag_from("0\n"), ReadinessSignal::Observed(false));
        for value in ["", "2", "true", "1\n0"] {
            assert_eq!(kernel_flag_from(value), ReadinessSignal::Invalid, "{value:?}");
        }
    }

    #[test]
    fn diagnostics_name_every_prerequisite_and_failure_without_file_contents() {
        for prerequisite in [
            Prerequisite::Kernel,
            Prerequisite::OpenSslProperties,
            Prerequisite::SystemPolicy,
        ] {
            for reason in [
                FailureReason::Disabled,
                FailureReason::Invalid,
                FailureReason::Missing,
                FailureReason::ReadFailed(ErrorKind::PermissionDenied),
                FailureReason::Unsupported,
            ] {
                let message = ReadinessFailure { prerequisite, reason }.to_string();
                assert!(message.contains("verify"), "{message}");
                assert!(
                    message.contains(match prerequisite {
                        Prerequisite::Kernel => KERNEL_FIPS_FLAG,
                        Prerequisite::OpenSslProperties => "EVP_default_properties_is_fips_enabled",
                        Prerequisite::SystemPolicy => CRYPTO_POLICIES_CONFIG,
                    }),
                    "{message}"
                );
            }
        }
    }

    #[test]
    fn check_uses_the_direct_effective_property_query() {
        let readiness = CryptoReadiness::check();
        assert_eq!(
            readiness.openssl_fips_properties,
            rustls_openssl::fips::default_properties_enabled()
                .map_or(ReadinessSignal::Unsupported, ReadinessSignal::Observed)
        );
        if std::env::var_os("PRAXIS_TEST_FIPS_PROVIDER").is_some() {
            assert_eq!(
                readiness.openssl_fips_properties,
                ReadinessSignal::Observed(true),
                "the declared FIPS-provider run must have effective fips=yes"
            );
        }
    }

    #[test]
    fn effective_properties_follow_process_configuration() {
        if rustls_openssl::fips::default_properties_enabled().is_none() {
            assert_eq!(
                CryptoReadiness::check().openssl_fips_properties,
                ReadinessSignal::Unsupported
            );
            return;
        }
        let directory = tempfile::tempdir().expect("isolated OpenSSL config");
        let config = directory.path().join("openssl.cnf");
        for selected in ["yes", "no"] {
            std::fs::write(&config, format!("openssl_conf = init\n[init]\nalg_section = properties\n[properties]\ndefault_properties = fips={selected}\n"))
                .expect("write effective property selection");
            let output = std::process::Command::new(std::env::current_exe().expect("unit test binary"))
                .args(["--exact", "crypto_readiness::tests::effective_properties_child"])
                .env("OPENSSL_CONF", &config)
                .env("PRAXIS_READINESS_EXPECTED", selected)
                .output()
                .expect("isolated readiness process");
            assert!(
                output.status.success(),
                "fips={selected}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn effective_properties_child() {
        let Ok(selected) = std::env::var("PRAXIS_READINESS_EXPECTED") else {
            return;
        };
        let readiness = CryptoReadiness::check();
        assert_eq!(
            readiness.openssl_fips_properties,
            ReadinessSignal::Observed(selected == "yes"),
            "the application must inspect the effective configuration"
        );
        if selected == "no" {
            assert!(!readiness.fips_ready(), "disabled properties cannot pass readiness");
            assert!(
                readiness
                    .unmet()
                    .iter()
                    .any(|failure| failure.prerequisite == Prerequisite::OpenSslProperties),
                "the direct-property failure is reported"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A supported host with every prerequisite enabled.
    fn ready() -> CryptoReadiness {
        CryptoReadiness {
            crypto_policy: ReadinessSignal::Observed(CryptoPolicy::Fips),
            kernel_fips: ReadinessSignal::Observed(true),
            openssl_fips_properties: ReadinessSignal::Observed(true),
        }
    }
}
