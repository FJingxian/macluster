use std::str::FromStr;

use macluster_protocol::identifiers::NodeId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageProtocol {
    Nfs,
    Smb,
}

impl StorageProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nfs => "nfs",
            Self::Smb => "smb",
        }
    }
}

impl std::fmt::Display for StorageProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for StorageProtocol {
    type Err = StorageUriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("nfs") {
            Ok(Self::Nfs)
        } else if value.eq_ignore_ascii_case("smb") {
            Ok(Self::Smb)
        } else {
            Err(StorageUriError::UnsupportedProtocol(value.to_owned()))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageUri {
    pub protocol: StorageProtocol,
    pub server: NodeId,
    pub source: String,
    pub canonical: String,
}

impl StorageUri {
    pub fn parse(value: &str) -> Result<Self, StorageUriError> {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(StorageUriError::Invalid(
                "URI contains no usable characters",
            ));
        }
        if value.contains('?') || value.contains('#') {
            return Err(StorageUriError::Invalid(
                "query strings and fragments are not supported",
            ));
        }
        let (protocol_text, remainder) = value
            .split_once("://")
            .ok_or(StorageUriError::MissingScheme)?;
        let protocol = protocol_text.parse()?;
        let (server_text, path_tail) = remainder
            .split_once('/')
            .ok_or(StorageUriError::MissingSourcePath)?;
        let server = NodeId::new(server_text.to_owned())
            .map_err(|_| StorageUriError::InvalidServer(server_text.to_owned()))?;
        let decoded = percent_decode(path_tail)?;
        if decoded.chars().any(char::is_control) {
            return Err(StorageUriError::Invalid(
                "decoded path contains control characters",
            ));
        }
        if decoded.contains('\\') {
            return Err(StorageUriError::Invalid(
                "backslashes are not valid in a storage URI path",
            ));
        }
        let normalized = decoded.trim_end_matches('/');
        if normalized.is_empty() {
            return Err(StorageUriError::MissingSourcePath);
        }
        let source = format!("/{normalized}");
        if source
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(StorageUriError::Invalid(
                "path must not contain empty, '.' or '..' components",
            ));
        }
        let canonical = format!("{protocol}://{server}{source}");
        Ok(Self {
            protocol,
            server,
            source,
            canonical,
        })
    }
}

impl std::fmt::Display for StorageUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.canonical)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StorageUriError {
    #[error("storage URI must begin with nfs:// or smb://")]
    MissingScheme,
    #[error("unsupported storage protocol '{0}'")]
    UnsupportedProtocol(String),
    #[error("storage URI is missing a source path")]
    MissingSourcePath,
    #[error("storage URI server '{0}' is not a valid node ID")]
    InvalidServer(String),
    #[error("invalid storage URI: {0}")]
    Invalid(&'static str),
    #[error("invalid percent escape in storage URI")]
    InvalidPercentEscape,
    #[error("storage URI path is not UTF-8")]
    InvalidUtf8,
}

fn percent_decode(value: &str) -> Result<String, StorageUriError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes
                .get(index + 1)
                .ok_or(StorageUriError::InvalidPercentEscape)?;
            let low = *bytes
                .get(index + 2)
                .ok_or(StorageUriError::InvalidPercentEscape)?;
            let high = hex_value(high).ok_or(StorageUriError::InvalidPercentEscape)?;
            let low = hex_value(low).ok_or(StorageUriError::InvalidPercentEscape)?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| StorageUriError::InvalidUtf8)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
