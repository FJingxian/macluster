use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

use ed25519_dalek::{Signer, SigningKey};
use macluster_protocol::identifiers::Id128;

const KEY_FILE: &str = "cluster-update.key";
const KEY_FORMAT: &str = "macluster-cluster-update-key-v1";

pub(crate) struct UpdateSigningKey {
    cluster_id: String,
    signing_key: SigningKey,
}

impl UpdateSigningKey {
    pub(crate) fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub(crate) fn sign_manifest(&self, bytes: &[u8]) -> [u8; 64] {
        self.signing_key.sign(bytes).to_bytes()
    }
}

pub(crate) fn ensure_cluster_update_key(
    state_dir: &Path,
    cluster_id: &str,
) -> Result<UpdateSigningKey, String> {
    let cluster_id = Id128::parse(cluster_id)
        .map_err(|error| format!("invalid cluster update key identity: {error}"))?
        .to_string();
    validate_state_dir(state_dir)?;

    let path = state_dir.join(KEY_FILE);
    match read_existing_key(&path, &cluster_id) {
        Ok(key) => return Ok(key),
        Err(ReadKeyError::Missing) => {}
        Err(ReadKeyError::Invalid(error)) => return Err(error),
    }

    let mut seed = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut seed))
        .map_err(|error| format!("cannot generate cluster update key: {error}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let contents = encode_key(&cluster_id, &signing_key.to_bytes());
    let temporary = state_dir.join(format!(".cluster-update-{}.next", Id128::random()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("cannot stage cluster update key: {error}"))?;
    if let Err(error) = file
        .write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot write cluster update key: {error}"));
    }
    drop(file);

    match fs::hard_link(&temporary, &path) {
        Ok(()) => {
            let _ = fs::remove_file(&temporary);
            File::open(state_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("cannot sync cluster update key directory: {error}"))?;
            Ok(UpdateSigningKey {
                cluster_id,
                signing_key,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            read_existing_key(&path, &cluster_id).map_err(ReadKeyError::message)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(format!("cannot install cluster update key: {error}"))
        }
    }
}

pub(crate) fn next_cluster_update_sequence(state_dir: &Path) -> Result<u64, String> {
    validate_state_dir(state_dir)?;
    let lock_path = state_dir.join(".cluster-update-sequence.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|error| format!("cannot open cluster update sequence lock: {error}"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "cannot lock cluster update sequence: {}",
            io::Error::last_os_error()
        ));
    }

    let sequence_path = state_dir.join("cluster-update.sequence");
    let current = match fs::symlink_metadata(&sequence_path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600 =>
        {
            fs::read_to_string(&sequence_path)
                .map_err(|error| format!("cannot read cluster update sequence: {error}"))?
                .trim()
                .parse::<u64>()
                .map_err(|_| "cluster update sequence is malformed".to_owned())?
        }
        Ok(_) => return Err("cluster update sequence has unsafe ownership or permissions".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(format!("cannot inspect cluster update sequence: {error}")),
    };
    let next = current
        .checked_add(1)
        .ok_or_else(|| "cluster update sequence is exhausted".to_owned())?;
    let temporary = state_dir.join(format!(".cluster-update-sequence-{}.next", Id128::random()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("cannot stage cluster update sequence: {error}"))?;
    if let Err(error) = writeln!(file, "{next}").and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot write cluster update sequence: {error}"));
    }
    drop(file);
    fs::rename(&temporary, &sequence_path)
        .map_err(|error| format!("cannot commit cluster update sequence: {error}"))?;
    File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync cluster update sequence: {error}"))?;
    Ok(next)
}

fn validate_state_dir(state_dir: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(state_dir).map_err(|error| {
        format!(
            "cannot inspect cluster update key directory {}: {error}",
            state_dir.display()
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "cluster update key directory {} has unsafe ownership or permissions",
            state_dir.display()
        ));
    }
    Ok(())
}

enum ReadKeyError {
    Missing,
    Invalid(String),
}

impl ReadKeyError {
    fn message(self) -> String {
        match self {
            Self::Missing => "cluster update key disappeared during creation".into(),
            Self::Invalid(error) => error,
        }
    }
}

fn read_existing_key(path: &Path, cluster_id: &str) -> Result<UpdateSigningKey, ReadKeyError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(ReadKeyError::Missing),
        Err(error) => {
            return Err(ReadKeyError::Invalid(format!(
                "cannot inspect cluster update key: {error}"
            )));
        }
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ReadKeyError::Invalid(
            "cluster update key has unsafe ownership, type, or permissions".into(),
        ));
    }
    let contents = fs::read_to_string(path).map_err(|error| {
        ReadKeyError::Invalid(format!("cannot read cluster update key: {error}"))
    })?;
    let mut lines = contents.lines();
    let format = lines.next();
    let saved_cluster_id = lines.next();
    let encoded_seed = lines.next();
    if format != Some(KEY_FORMAT) || saved_cluster_id != Some(cluster_id) || lines.next().is_some()
    {
        return Err(ReadKeyError::Invalid(
            "cluster update key is malformed or belongs to another cluster".into(),
        ));
    }
    let seed = decode_seed(encoded_seed.unwrap_or_default()).ok_or_else(|| {
        ReadKeyError::Invalid("cluster update key contains an invalid private key".into())
    })?;
    Ok(UpdateSigningKey {
        cluster_id: cluster_id.to_owned(),
        signing_key: SigningKey::from_bytes(&seed),
    })
}

fn encode_key(cluster_id: &str, seed: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in seed {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    format!("{KEY_FORMAT}\n{cluster_id}\n{encoded}\n")
}

fn decode_seed(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 {
        return None;
    }
    let mut seed = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        seed[index] = (high << 4) | low;
    }
    Some(seed)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

    use macluster_protocol::identifiers::Id128;

    use super::{ensure_cluster_update_key, next_cluster_update_sequence};

    fn test_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "macluster-update-signing-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn creates_a_private_key_and_reuses_it_for_the_same_cluster() {
        let root = test_dir();
        let cluster_id = Id128::random().to_string();
        let key = ensure_cluster_update_key(&root, &cluster_id).unwrap();
        let metadata = fs::metadata(root.join("cluster-update.key")).unwrap();

        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o777, 0o600);

        let message = b"helper update manifest";
        let signature = key.sign_manifest(message);
        let public = ed25519_dalek::VerifyingKey::from_bytes(&key.public_key_bytes()).unwrap();
        use ed25519_dalek::Verifier;
        public
            .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();

        let second = ensure_cluster_update_key(&root, &cluster_id).unwrap();
        assert_eq!(key.public_key_bytes(), second.public_key_bytes());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_malformed_or_cross_cluster_signing_keys() {
        let root = test_dir();
        let key_path = root.join("cluster-update.key");
        let first_cluster = Id128::random().to_string();
        ensure_cluster_update_key(&root, &first_cluster).unwrap();

        let other_cluster = Id128::random().to_string();
        assert!(ensure_cluster_update_key(&root, &other_cluster).is_err());

        fs::write(&key_path, b"not a macluster update key\n").unwrap();
        assert!(ensure_cluster_update_key(&root, &first_cluster).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_sequence_is_monotonic_and_persisted() {
        let root = test_dir();
        assert_eq!(next_cluster_update_sequence(&root).unwrap(), 1);
        assert_eq!(next_cluster_update_sequence(&root).unwrap(), 2);
        assert_eq!(
            fs::read_to_string(root.join("cluster-update.sequence")).unwrap(),
            "2\n"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
