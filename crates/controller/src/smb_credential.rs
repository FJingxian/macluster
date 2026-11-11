use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use macluster_protocol::smb_credential::{
    MAX_SMB_CREDENTIAL_FRAME_BYTES, SMB_CREDENTIAL_SERVICE_VERSION, SecretString, SmbCredentialKey,
    SmbCredentialOperation, SmbCredentialReply, SmbCredentialReplyBody, SmbCredentialRequest,
    StoredSmbCredential,
};
use thiserror::Error;

pub const SMB_CREDENTIAL_SOCKET_PATH: &str = "/var/run/org.macluster.smb-credential.sock";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct CredentialHelperClient {
    socket: PathBuf,
    timeout: Duration,
}

impl CredentialHelperClient {
    pub fn system() -> Self {
        Self::new(SMB_CREDENTIAL_SOCKET_PATH, CLIENT_TIMEOUT)
    }

    pub fn new(socket: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            socket: socket.into(),
            timeout,
        }
    }

    pub fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Put {
            key: key.clone(),
            password: password.clone(),
        })? {
            SmbCredentialReplyBody::Credential(credential) => Ok(credential),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "put",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn get(
        &self,
        key: &SmbCredentialKey,
    ) -> Result<Option<StoredSmbCredential>, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Get { key: key.clone() })? {
            SmbCredentialReplyBody::Credential(credential) => Ok(Some(credential)),
            SmbCredentialReplyBody::Missing => Ok(None),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "get",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn import(
        &self,
        key: &SmbCredentialKey,
        credential: &StoredSmbCredential,
    ) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Import {
            key: key.clone(),
            credential: credential.clone(),
        })? {
            SmbCredentialReplyBody::Credential(_) => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "import",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn delete(&self, key: &SmbCredentialKey) -> Result<bool, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Delete { key: key.clone() })? {
            SmbCredentialReplyBody::Deleted(deleted) => Ok(deleted),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "delete",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn ping(&self) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Ping)? {
            SmbCredentialReplyBody::Pong => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "ping",
                reply: reply_name(&other),
            }),
        }
    }

    fn call(
        &self,
        operation: SmbCredentialOperation,
    ) -> Result<SmbCredentialReplyBody, SmbCredentialClientError> {
        call_at(&self.socket, self.timeout, operation)
    }
}

pub fn put_smb_credential(
    key: &SmbCredentialKey,
    password: &SecretString,
) -> Result<StoredSmbCredential, SmbCredentialClientError> {
    CredentialHelperClient::system().put(key, password)
}

pub fn get_smb_credential(
    key: &SmbCredentialKey,
) -> Result<Option<StoredSmbCredential>, SmbCredentialClientError> {
    CredentialHelperClient::system().get(key)
}

pub fn import_smb_credential(
    key: &SmbCredentialKey,
    credential: &StoredSmbCredential,
) -> Result<(), SmbCredentialClientError> {
    CredentialHelperClient::system().import(key, credential)
}

pub fn delete_smb_credential(key: &SmbCredentialKey) -> Result<bool, SmbCredentialClientError> {
    CredentialHelperClient::system().delete(key)
}

pub fn ping_smb_credential() -> Result<(), SmbCredentialClientError> {
    CredentialHelperClient::system().ping()
}

fn call_at(
    socket: &Path,
    timeout: Duration,
    operation: SmbCredentialOperation,
) -> Result<SmbCredentialReplyBody, SmbCredentialClientError> {
    let request = SmbCredentialRequest::new(operation);
    request
        .validate()
        .map_err(|error| SmbCredentialClientError::InvalidRequest(error.to_string()))?;
    let bytes = serde_json::to_vec(&request).map_err(|_| {
        SmbCredentialClientError::InvalidRequest("request serialization failed".into())
    })?;
    if bytes.len() > MAX_SMB_CREDENTIAL_FRAME_BYTES {
        return Err(SmbCredentialClientError::FrameTooLarge);
    }
    let mut stream = UnixStream::connect(socket).map_err(SmbCredentialClientError::Io)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(SmbCredentialClientError::Io)?;
    stream
        .write_all(&bytes)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|error| classify_io(error, timeout))?;
    let mut reply_bytes = Vec::new();
    stream
        .take(MAX_SMB_CREDENTIAL_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut reply_bytes)
        .map_err(|error| classify_io(error, timeout))?;
    if reply_bytes.len() > MAX_SMB_CREDENTIAL_FRAME_BYTES {
        return Err(SmbCredentialClientError::FrameTooLarge);
    }
    let reply: SmbCredentialReply =
        serde_json::from_slice(&reply_bytes).map_err(|_| SmbCredentialClientError::InvalidReply)?;
    if reply.service_version != SMB_CREDENTIAL_SERVICE_VERSION {
        return Err(SmbCredentialClientError::ServiceVersion {
            expected: SMB_CREDENTIAL_SERVICE_VERSION,
            actual: reply.service_version,
        });
    }
    reply.result.map_err(SmbCredentialClientError::Remote)
}

fn classify_io(error: std::io::Error, timeout: Duration) -> SmbCredentialClientError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        SmbCredentialClientError::Timeout(timeout)
    } else {
        SmbCredentialClientError::Io(error)
    }
}

fn reply_name(reply: &SmbCredentialReplyBody) -> &'static str {
    match reply {
        SmbCredentialReplyBody::Pong => "pong",
        SmbCredentialReplyBody::Credential(_) => "credential",
        SmbCredentialReplyBody::Missing => "missing",
        SmbCredentialReplyBody::Deleted(_) => "deleted",
    }
}

#[derive(Debug, Error)]
pub enum SmbCredentialClientError {
    #[error("SMB credential helper I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("SMB credential helper timed out after {0:?}")]
    Timeout(Duration),
    #[error("SMB credential request is invalid: {0}")]
    InvalidRequest(String),
    #[error("SMB credential helper returned an invalid reply")]
    InvalidReply,
    #[error("SMB credential helper frame exceeds the configured limit")]
    FrameTooLarge,
    #[error("SMB credential helper service version {actual} does not match {expected}")]
    ServiceVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("SMB credential helper rejected the request: {0}")]
    Remote(String),
    #[error("SMB credential helper returned {reply} for {operation}")]
    UnexpectedReply {
        operation: &'static str,
        reply: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        path::PathBuf,
        time::Duration,
    };

    use macluster_protocol::{
        identifiers::{Id128, NodeId},
        smb_credential::{
            MAX_SMB_CREDENTIAL_FRAME_BYTES, SMB_CREDENTIAL_SERVICE_VERSION, SecretString,
            SmbCredentialKey, SmbCredentialOperation, SmbCredentialReply, SmbCredentialReplyBody,
            SmbCredentialRequest, StoredSmbCredential,
        },
    };

    use super::{CredentialHelperClient, SmbCredentialClientError};

    fn socket_path() -> (PathBuf, PathBuf) {
        let root = PathBuf::from("/tmp").join(format!(
            "mc-cred-{}-{}",
            std::process::id(),
            &Id128::random().to_string()[..8]
        ));
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join("credential.sock");
        (root, socket)
    }

    fn key() -> SmbCredentialKey {
        SmbCredentialKey {
            cluster_uuid: Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            server_id: NodeId::new("nas-01").unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        }
    }

    fn read_request(stream: &mut std::os::unix::net::UnixStream) -> SmbCredentialRequest {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn write_reply(stream: &mut std::os::unix::net::UnixStream, body: SmbCredentialReplyBody) {
        stream
            .write_all(&serde_json::to_vec(&SmbCredentialReply::success(body)).unwrap())
            .unwrap();
    }

    #[test]
    fn helper_client_round_trips_put_get_import_delete_and_missing() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut stored: Option<StoredSmbCredential> = None;
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                match read_request(&mut stream).operation {
                    SmbCredentialOperation::Put { password, .. } => {
                        stored = Some(StoredSmbCredential {
                            generation: 1,
                            password,
                        });
                        write_reply(
                            &mut stream,
                            SmbCredentialReplyBody::Credential(stored.as_ref().unwrap().clone()),
                        );
                    }
                    SmbCredentialOperation::Get { .. } => {
                        write_reply(
                            &mut stream,
                            stored
                                .as_ref()
                                .map(|credential| {
                                    SmbCredentialReplyBody::Credential(credential.clone())
                                })
                                .unwrap_or(SmbCredentialReplyBody::Missing),
                        );
                    }
                    SmbCredentialOperation::Import { credential, .. } => {
                        stored = Some(credential.clone());
                        write_reply(&mut stream, SmbCredentialReplyBody::Credential(credential));
                    }
                    SmbCredentialOperation::Delete { .. } => {
                        let removed = stored.take().is_some();
                        write_reply(&mut stream, SmbCredentialReplyBody::Deleted(removed));
                    }
                    SmbCredentialOperation::Ping => {
                        write_reply(&mut stream, SmbCredentialReplyBody::Pong);
                    }
                }
            }
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        assert_eq!(client.get(&key()).unwrap(), None);
        assert_eq!(
            client
                .put(&key(), &SecretString::new("test-secret-one"))
                .unwrap()
                .generation,
            1
        );
        assert_eq!(
            client.get(&key()).unwrap().unwrap().password.as_secret(),
            "test-secret-one"
        );
        client
            .import(
                &key(),
                &StoredSmbCredential {
                    generation: 9,
                    password: SecretString::new("test-secret-nine"),
                },
            )
            .unwrap();
        assert_eq!(client.get(&key()).unwrap().unwrap().generation, 9);
        assert!(client.delete(&key()).unwrap());
        assert_eq!(client.get(&key()).unwrap(), None);

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_rejects_service_version_mismatch_without_secret_text() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            stream
                .write_all(
                    &serde_json::to_vec(&SmbCredentialReply {
                        service_version: "wrong-version".into(),
                        result: Err("do-not-log-test-secret".into()),
                    })
                    .unwrap(),
                )
                .unwrap();
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        let error = client
            .put(&key(), &SecretString::new("test-secret"))
            .unwrap_err();
        assert!(matches!(
            error,
            SmbCredentialClientError::ServiceVersion { .. }
        ));
        assert!(!format!("{error:?}").contains("test-secret"));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_bounds_replies_before_decoding() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            let _ = stream.write_all(&vec![b'x'; MAX_SMB_CREDENTIAL_FRAME_BYTES + 1]);
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        let error = client.get(&key()).unwrap_err();
        assert!(matches!(error, SmbCredentialClientError::FrameTooLarge));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_uses_the_current_service_version_in_requests() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert_eq!(request.service_version, SMB_CREDENTIAL_SERVICE_VERSION);
            write_reply(&mut stream, SmbCredentialReplyBody::Pong);
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        client.ping().unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
}
