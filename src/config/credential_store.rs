use std::fmt;

/// Service identifier used as the Keychain "service" attribute.
/// Acts as a namespace so credentials do not collide with other apps.
pub const SERVICE: &str = "dev.falcon-cli";

/// Logical identifier for the OAuth2 client_secret entry. This is the
/// label / key used to look the entry up in the store; it is NOT the
/// secret value itself.
pub const KEY_CLIENT_SECRET: &str = "client_secret";

#[derive(Debug)]
pub enum StoreError {
    /// The backend (e.g. Keychain) is not available on this platform.
    Unavailable(String),
    /// An I/O or backend error occurred while accessing the store.
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable(s) => write!(f, "credential store unavailable: {}", s),
            StoreError::Backend(s) => write!(f, "credential store error: {}", s),
        }
    }
}

impl std::error::Error for StoreError {}

/// Abstract storage backend for sensitive credentials.
///
/// `key` is the entry's identifier (e.g. "client_secret"), not the
/// credential value. `get` returns `Ok(None)` when the entry simply does
/// not exist (a normal state during fallback to the next source).
/// Backend-level failures must be surfaced as `Err` so callers can
/// distinguish "not stored" from "store unreachable".
pub trait CredentialStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::{CredentialStore, StoreError, SERVICE};
    use keyring::Entry;

    pub struct KeychainStore;

    impl KeychainStore {
        pub fn new() -> Self {
            Self
        }

        fn entry(key: &str) -> Result<Entry, StoreError> {
            // The Keychain API names the second slot "account"; we use our
            // logical key as the account string.
            Entry::new(SERVICE, key).map_err(|e| StoreError::Backend(e.to_string()))
        }
    }

    impl Default for KeychainStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for KeychainStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            let entry = Self::entry(key)?;
            match entry.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }

        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            let entry = Self::entry(key)?;
            entry.set_password(value).map_err(classify_keyring_err)
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            let entry = Self::entry(key)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }
    }

    /// `errSecNoDefaultKeychain` from `Security.framework`.
    /// See <https://developer.apple.com/documentation/security/errsecnodefaultkeychain>.
    /// Locale-independent: the OSStatus is the same on every macOS install.
    pub(super) const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;
    pub(super) const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;

    /// Classify a `keyring::Error` into `Unavailable` (the store as a whole
    /// is not present, e.g. CI sandbox without a default keychain) vs
    /// `Backend` (an actual access failure that the user should investigate
    /// — denied prompt, daemon down, ACL mismatch).
    ///
    /// We prefer to classify by OSStatus via downcasting the boxed source
    /// of `keyring::Error::PlatformFailure` to `security_framework::base::Error`.
    /// String-matching on the `Display` output is locale-translated on
    /// Japanese / other macOS locales and would misclassify those users as
    /// `Backend`, blocking the toml fallback on a clean machine. String
    /// match survives only as a last-resort fallback.
    pub(super) fn classify_keyring_err(e: keyring::Error) -> StoreError {
        if let keyring::Error::PlatformFailure(ref src) = e {
            // `keyring` boxes the platform error as `Box<dyn Error + Send + Sync>`.
            // On macOS (apple-native backend) this is a `security_framework::base::Error`.
            if let Some(sf) = src
                .source()
                .and_then(|s| s.downcast_ref::<security_framework::base::Error>())
                .or_else(|| {
                    // Some keyring paths box the sf error directly without wrapping.
                    (src.as_ref() as &dyn std::error::Error)
                        .downcast_ref::<security_framework::base::Error>()
                })
            {
                let code = sf.code();
                if code == ERR_SEC_NO_DEFAULT_KEYCHAIN || code == ERR_SEC_INVALID_KEYCHAIN {
                    return StoreError::Unavailable(format!(
                        "no default keychain (OSStatus {})",
                        code
                    ));
                }
                return StoreError::Backend(format!("OSStatus {}: {}", code, e));
            }
        }

        // Last-resort: locale-dependent string match so the logic still
        // works if the downcast above fails (e.g. keyring upgrades to a
        // security-framework major that does not match our pinned one).
        let msg = e.to_string();
        let lower = msg.to_lowercase();
        let unavailable = lower.contains("no default keychain")
            || lower.contains("default keychain could not be found")
            || lower.contains("no platform credential store");
        if unavailable {
            StoreError::Unavailable(msg)
        } else {
            StoreError::Backend(msg)
        }
    }
}

#[cfg(target_os = "macos")]
pub use keychain::KeychainStore;

/// Returns the platform's default credential store, or `None` if no
/// secure store backend is available on this build target.
pub fn default_store() -> Option<Box<dyn CredentialStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(KeychainStore::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(test)]
pub mod test_support {
    use super::{CredentialStore, StoreError};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `CredentialStore` used by tests.
    pub struct MemoryStore {
        inner: Mutex<HashMap<String, String>>,
    }

    impl MemoryStore {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    impl Default for MemoryStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for MemoryStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            Ok(self.inner.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            self.inner
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemoryStore;
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.get("k").unwrap().is_none());
        s.set("k", "v").unwrap();
        assert_eq!(s.get("k").unwrap().as_deref(), Some("v"));
        s.delete("k").unwrap();
        assert!(s.get("k").unwrap().is_none());
    }

    #[test]
    fn memory_store_delete_missing_is_ok() {
        let s = MemoryStore::new();
        s.delete("missing").unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_keyring_err_recognizes_no_default_keychain_by_osstatus() {
        let sf_err =
            security_framework::base::Error::from_code(keychain::ERR_SEC_NO_DEFAULT_KEYCHAIN);
        let keyring_err = keyring::Error::PlatformFailure(Box::new(sf_err));
        let classified = keychain::classify_keyring_err(keyring_err);
        assert!(
            matches!(classified, StoreError::Unavailable(_)),
            "expected Unavailable, got {:?}",
            classified
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_keyring_err_treats_other_osstatus_as_backend() {
        // -25300 = errSecItemNotFound, not a "no keychain at all" error —
        // should be Backend so the user sees it.
        let sf_err = security_framework::base::Error::from_code(-25300);
        let keyring_err = keyring::Error::PlatformFailure(Box::new(sf_err));
        let classified = keychain::classify_keyring_err(keyring_err);
        assert!(
            matches!(classified, StoreError::Backend(_)),
            "expected Backend, got {:?}",
            classified
        );
    }
}
