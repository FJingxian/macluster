use std::{fmt, net::Ipv4Addr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::identifiers::{Id128, NodeId};

pub const SMB_CREDENTIAL_SERVICE_VERSION: &str = "smb-credential-1";
pub const MAX_SMB_CREDENTIAL_BYTES: usize = 4096;
pub const MAX_SMB_CREDENTIAL_FRAME_BYTES: usize = 32 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SmbCredentialValidationError> {
        let bytes = Zeroizing::new(bytes);
        let value = std::str::from_utf8(bytes.as_slice())
            .map_err(|_| SmbCredentialValidationError::SecretNotUtf8)?;
        let secret = Self::new(value.to_owned());
        secret.validate()?;
        Ok(secret)
    }

    pub fn as_secret(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return Err(SmbCredentialValidationError::EmptySecret);
        }
        if bytes.len() > MAX_SMB_CREDENTIAL_BYTES {
            return Err(SmbCredentialValidationError::SecretTooLong {
                maximum: MAX_SMB_CREDENTIAL_BYTES,
            });
        }
        if bytes
            .iter()
            .any(|byte| matches!(*byte, b'\0' | b'\n' | b'\r'))
        {
            return Err(SmbCredentialValidationError::SecretContainsLineOrNul);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(<redacted>)")
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_secret())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let secret = Self::from_bytes(String::deserialize(deserializer)?.into_bytes())
            .map_err(D::Error::custom)?;
        Ok(secret)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmbCredentialKey {
    pub cluster_uuid: Id128,
    pub server_id: NodeId,
    pub server_host: String,
    pub account: String,
}

impl SmbCredentialKey {
    pub fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        let host = self
            .server_host
            .parse::<Ipv4Addr>()
            .map_err(|_| SmbCredentialValidationError::InvalidServerHost)?;
        if host.is_unspecified() || host.is_multicast() || host == Ipv4Addr::BROADCAST {
            return Err(SmbCredentialValidationError::InvalidServerHost);
        }
        validate_account(&self.account)?;
        if self.server_id.as_str().is_empty() {
            return Err(SmbCredentialValidationError::InvalidServerId);
        }
        Ok(())
    }

    pub fn service_name(&self) -> String {
        format!("org.macluster.smb.{}.{}", self.cluster_uuid, self.server_id)
    }

    pub fn keychain_account(&self) -> String {
        format!("{}@{}", self.account, self.server_host)
    }

    pub fn endpoint(&self) -> SmbKeychainEndpoint {
        SmbKeychainEndpoint {
            server: self.server_host.clone(),
            account: self.account.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredSmbCredential {
    pub generation: u64,
    pub password: SecretString,
}

impl StoredSmbCredential {
    pub fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        if self.generation == 0 {
            return Err(SmbCredentialValidationError::GenerationZero);
        }
        self.password.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SmbKeychainEndpoint {
    pub server: String,
    pub account: String,
}

impl SmbKeychainEndpoint {
    pub fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        let host = self
            .server
            .parse::<Ipv4Addr>()
            .map_err(|_| SmbCredentialValidationError::InvalidServerHost)?;
        if host.is_unspecified() || host.is_multicast() || host == Ipv4Addr::BROADCAST {
            return Err(SmbCredentialValidationError::InvalidServerHost);
        }
        validate_account(&self.account)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmbCredentialProvision {
    pub key: SmbCredentialKey,
    pub credential: StoredSmbCredential,
}

impl SmbCredentialProvision {
    pub fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        self.key.validate()?;
        self.credential.validate()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
pub enum SmbCredentialOperation {
    Ping,
    Put {
        key: SmbCredentialKey,
        password: SecretString,
    },
    Get {
        key: SmbCredentialKey,
    },
    Import {
        key: SmbCredentialKey,
        credential: StoredSmbCredential,
    },
    Delete {
        key: SmbCredentialKey,
    },
}

impl SmbCredentialOperation {
    pub fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        match self {
            Self::Ping => Ok(()),
            Self::Put { key, password } => {
                key.validate()?;
                password.validate()
            }
            Self::Get { key } | Self::Delete { key } => key.validate(),
            Self::Import { key, credential } => {
                key.validate()?;
                credential.validate()
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SmbCredentialRequest {
    pub service_version: String,
    pub operation: SmbCredentialOperation,
}

impl SmbCredentialRequest {
    pub fn new(operation: SmbCredentialOperation) -> Self {
        Self {
            service_version: SMB_CREDENTIAL_SERVICE_VERSION.into(),
            operation,
        }
    }

    pub fn validate(&self) -> Result<(), SmbCredentialValidationError> {
        if self.service_version != SMB_CREDENTIAL_SERVICE_VERSION {
            return Err(SmbCredentialValidationError::IncompatibleServiceVersion);
        }
        self.operation.validate()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum SmbCredentialReplyBody {
    Pong,
    Credential(StoredSmbCredential),
    Missing,
    Deleted(bool),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SmbCredentialReply {
    pub service_version: String,
    pub result: Result<SmbCredentialReplyBody, String>,
}

impl SmbCredentialReply {
    pub fn success(body: SmbCredentialReplyBody) -> Self {
        Self {
            service_version: SMB_CREDENTIAL_SERVICE_VERSION.into(),
            result: Ok(body),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            service_version: SMB_CREDENTIAL_SERVICE_VERSION.into(),
            result: Err(error.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SmbCredentialValidationError {
    #[error("SMB credential service version is incompatible")]
    IncompatibleServiceVersion,
    #[error("SMB credential secret is empty")]
    EmptySecret,
    #[error("SMB credential secret exceeds {maximum} bytes")]
    SecretTooLong { maximum: usize },
    #[error("SMB credential secret is not UTF-8")]
    SecretNotUtf8,
    #[error("SMB credential secret contains a NUL or line terminator")]
    SecretContainsLineOrNul,
    #[error("SMB credential generation must be greater than zero")]
    GenerationZero,
    #[error("SMB server host must be a unicast IPv4 address")]
    InvalidServerHost,
    #[error("SMB server node id is invalid")]
    InvalidServerId,
    #[error("SMB account must contain 1 to 64 safe ASCII characters")]
    InvalidAccount,
}

fn validate_account(account: &str) -> Result<(), SmbCredentialValidationError> {
    if account.is_empty()
        || account.len() > 64
        || !account.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphanumeric() || byte == b'_'
            } else {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
            }
        })
    {
        return Err(SmbCredentialValidationError::InvalidAccount);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SMB_CREDENTIAL_BYTES, MAX_SMB_CREDENTIAL_FRAME_BYTES, SecretString, SmbCredentialKey,
        SmbCredentialProvision, StoredSmbCredential,
    };
    use crate::{
        identifiers::{Id128, NodeId},
        types::Operation,
    };
    use serde_json::{Value, json};

    fn key() -> SmbCredentialKey {
        SmbCredentialKey {
            cluster_uuid: Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            server_id: NodeId::new("nas-01").unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        }
    }

    fn provision(password: SecretString) -> SmbCredentialProvision {
        SmbCredentialProvision {
            key: key(),
            credential: StoredSmbCredential {
                generation: 1,
                password,
            },
        }
    }

    #[test]
    fn secret_debug_output_is_always_redacted() {
        assert_eq!(
            format!("{:?}", SecretString::new("do-not-print")),
            "SecretString(<redacted>)"
        );
        assert!(
            !format!("{:?}", provision(SecretString::new("do-not-print"))).contains("do-not-print")
        );
    }

    #[test]
    fn credential_key_accepts_only_canonical_noncontrol_identity_values() {
        assert!(key().validate().is_ok());

        let mut control_character = key();
        control_character.server_host = "192.0.2.20\n".into();
        assert!(control_character.validate().is_err());

        assert!(
            serde_json::from_value::<Id128>(json!("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")).is_ok(),
            "typed UUID parsing canonicalizes letter case"
        );
        assert!(serde_json::from_value::<Id128>(json!("not-a-uuid")).is_err());
    }

    #[test]
    fn stored_credential_rejects_generation_zero() {
        let credential = StoredSmbCredential {
            generation: 0,
            password: SecretString::new("secret"),
        };

        assert!(credential.validate().is_err());
    }

    #[test]
    fn secret_input_enforces_size_utf8_and_single_line_rules() {
        assert!(SecretString::from_bytes(vec![b'x'; MAX_SMB_CREDENTIAL_BYTES + 1]).is_err());
        assert!(SecretString::from_bytes(b"line-one\nline-two".to_vec()).is_err());
        assert!(SecretString::from_bytes(b"line-one\rline-two".to_vec()).is_err());
        assert!(SecretString::from_bytes(b"line-one\0line-two".to_vec()).is_err());
        assert!(SecretString::from_bytes(vec![0xff]).is_err());
        assert!(SecretString::from_bytes(b"valid secret".to_vec()).is_ok());
    }

    #[test]
    fn maximally_escaped_password_fits_the_transport_frame() {
        let encoded = serde_json::to_vec(&provision(SecretString::new(
            "\"".repeat(MAX_SMB_CREDENTIAL_BYTES),
        )))
        .unwrap();

        assert!(encoded.len() < MAX_SMB_CREDENTIAL_FRAME_BYTES);
    }

    #[test]
    fn legacy_reconcile_nfs_without_credential_fields_deserializes() {
        let legacy: Value = json!({
            "type": "reconcile_nfs",
            "payload": {
                "controller": {
                    "controller_uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "epoch": 7
                },
                "config_toml": "[cluster]\nname = \"test\"\n",
                "obsolete_mounts": [],
                "obsolete_aliases": [],
                "obsolete_markers": [],
                "obsolete_exports": []
            }
        });

        let operation: Operation = serde_json::from_value(legacy).unwrap();
        assert!(matches!(operation, Operation::ReconcileNfs { .. }));
    }
}
