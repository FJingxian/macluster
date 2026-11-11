#[cfg(test)]
use std::path::Path;

use macluster_protocol::smb_credential::{SecretString, SmbCredentialValidationError};
use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
use thiserror::Error;

const SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_NO_ACCESS_FOR_ITEM: i32 = -25243;

pub struct MacKeychain {
    keychain: SecKeychain,
    _interaction_lock: Option<KeychainUserInteractionLock>,
}

impl MacKeychain {
    pub fn system() -> Result<Self, KeychainCredentialError> {
        let keychain = SecKeychain::open(SYSTEM_KEYCHAIN_PATH)
            .map_err(KeychainCredentialError::from_security)?;
        Ok(Self {
            keychain,
            _interaction_lock: Some(
                SecKeychain::disable_user_interaction()
                    .map_err(KeychainCredentialError::from_security)?,
            ),
        })
    }

    #[cfg(test)]
    pub fn at(path: &Path) -> Result<Self, KeychainCredentialError> {
        Ok(Self {
            keychain: SecKeychain::open(path).map_err(KeychainCredentialError::from_security)?,
            _interaction_lock: None,
        })
    }

    pub fn set_generic_secret(
        &self,
        service: &str,
        account: &str,
        secret: &SecretString,
    ) -> Result<(), KeychainCredentialError> {
        self.keychain
            .set_generic_password(service, account, secret.as_secret().as_bytes())
            .map_err(KeychainCredentialError::from_security)
    }

    pub fn get_generic_secret(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretString>, KeychainCredentialError> {
        match self.keychain.find_generic_password(service, account) {
            Ok((password, _)) => SecretString::from_bytes(password.as_ref().to_vec())
                .map(Some)
                .map_err(KeychainCredentialError::InvalidSecret),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(KeychainCredentialError::from_security(error)),
        }
    }

    pub fn delete_generic_secret(
        &self,
        service: &str,
        account: &str,
    ) -> Result<bool, KeychainCredentialError> {
        match self.keychain.find_generic_password(service, account) {
            Ok((_, item)) => {
                item.delete();
                Ok(true)
            }
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(KeychainCredentialError::from_security(error)),
        }
    }

    pub fn has_generic_secret(
        &self,
        service: &str,
        account: &str,
    ) -> Result<bool, KeychainCredentialError> {
        match self.keychain.find_generic_password(service, account) {
            Ok(_) => Ok(true),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(KeychainCredentialError::from_security(error)),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KeychainCredentialError {
    #[error("Keychain interaction is not allowed")]
    InteractionNotAllowed,
    #[error("Keychain authentication failed")]
    AuthenticationFailed,
    #[error("Keychain item access was denied")]
    NoAccess,
    #[error("Keychain returned status {status}: {message}")]
    Security { status: i32, message: String },
    #[error("Keychain returned an invalid credential: {0}")]
    InvalidSecret(SmbCredentialValidationError),
}

impl KeychainCredentialError {
    #[cfg(test)]
    pub(crate) fn from_status(status: i32) -> Self {
        match status {
            ERR_SEC_INTERACTION_NOT_ALLOWED => Self::InteractionNotAllowed,
            ERR_SEC_AUTH_FAILED => Self::AuthenticationFailed,
            ERR_SEC_NO_ACCESS_FOR_ITEM => Self::NoAccess,
            _ => Self::Security {
                status,
                message: "unspecified Security.framework error".into(),
            },
        }
    }

    fn from_security(error: security_framework::base::Error) -> Self {
        match error.code() {
            ERR_SEC_INTERACTION_NOT_ALLOWED => Self::InteractionNotAllowed,
            ERR_SEC_AUTH_FAILED => Self::AuthenticationFailed,
            ERR_SEC_NO_ACCESS_FOR_ITEM => Self::NoAccess,
            status => Self::Security {
                status,
                message: error.message().unwrap_or_else(|| "unknown error".into()),
            },
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use macluster_protocol::smb_credential::SecretString;
    use security_framework::os::macos::keychain::CreateOptions;

    use super::{KeychainCredentialError, MacKeychain};

    fn temporary_keychain() -> (std::path::PathBuf, MacKeychain) {
        let path = std::env::temp_dir().join(format!(
            "macluster-keychain-{}-{}.keychain",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut options = CreateOptions::new();
        options.password("test-keychain-password");
        options.create(&path).unwrap();
        let keychain = MacKeychain::at(&path).unwrap();
        (path, keychain)
    }

    #[test]
    fn generic_secret_round_trip_updates_and_deletes_one_item() {
        let (path, keychain) = temporary_keychain();
        assert!(!keychain.has_generic_secret("service", "account").unwrap());

        keychain
            .set_generic_secret("service", "account", &SecretString::new("secret-one"))
            .unwrap();
        assert_eq!(
            keychain
                .get_generic_secret("service", "account")
                .unwrap()
                .unwrap()
                .as_secret(),
            "secret-one"
        );

        keychain
            .set_generic_secret("service", "account", &SecretString::new("secret-two"))
            .unwrap();
        assert_eq!(
            keychain
                .get_generic_secret("service", "account")
                .unwrap()
                .unwrap()
                .as_secret(),
            "secret-two"
        );

        assert!(
            keychain
                .delete_generic_secret("service", "account")
                .unwrap()
        );
        assert!(
            keychain
                .get_generic_secret("service", "account")
                .unwrap()
                .is_none()
        );
        assert!(
            !keychain
                .delete_generic_secret("service", "account")
                .unwrap()
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn interaction_and_authorization_errors_are_typed_without_secret_text() {
        let error = KeychainCredentialError::from_status(-25308);
        assert!(matches!(
            error,
            KeychainCredentialError::InteractionNotAllowed
        ));
        assert!(!format!("{error:?}").contains("secret-one"));

        assert!(matches!(
            KeychainCredentialError::from_status(-25293),
            KeychainCredentialError::AuthenticationFailed
        ));
        assert!(matches!(
            KeychainCredentialError::from_status(-25243),
            KeychainCredentialError::NoAccess
        ));
    }

    #[test]
    #[ignore]
    fn smb_keychain_system_round_trip() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test with sudo");
        let keychain = MacKeychain::system().unwrap();
        let service = format!("org.macluster.test.system-keychain.{}", std::process::id());
        let account = "macluster-test";

        let _ = keychain.delete_generic_secret(&service, account);
        keychain
            .set_generic_secret(&service, account, &SecretString::new("round-trip-one"))
            .unwrap();
        assert_eq!(
            keychain
                .get_generic_secret(&service, account)
                .unwrap()
                .unwrap()
                .as_secret(),
            "round-trip-one"
        );
        keychain
            .set_generic_secret(&service, account, &SecretString::new("round-trip-two"))
            .unwrap();
        assert_eq!(
            keychain
                .get_generic_secret(&service, account)
                .unwrap()
                .unwrap()
                .as_secret(),
            "round-trip-two"
        );
        assert!(keychain.delete_generic_secret(&service, account).unwrap());
        assert!(
            keychain
                .get_generic_secret(&service, account)
                .unwrap()
                .is_none()
        );
    }
}
