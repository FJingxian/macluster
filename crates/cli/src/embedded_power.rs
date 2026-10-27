//! Release payload, extracted only when configuring or inspecting the helper.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use macluster_protocol::{framing::sha256_hex, identifiers::Id128};

const PAYLOAD: &[u8] = include_bytes!(env!("MACLUSTER_EMBEDDED_POWER"));

pub(crate) fn digest() -> Result<String, String> {
    sha256_hex(PAYLOAD).map_err(|error| error.to_string())
}

pub(crate) struct ExtractedHelper {
    directory: PathBuf,
    path: PathBuf,
}

impl ExtractedHelper {
    pub(crate) fn new() -> Result<Self, String> {
        Self::in_directory(&std::env::temp_dir())
            .map_err(|error| format!("could not extract embedded power helper: {error}"))
    }

    fn in_directory(parent: &Path) -> io::Result<Self> {
        let directory = parent.join(format!("macluster-helper-{}", Id128::random()));
        DirBuilder::new().mode(0o700).create(&directory)?;
        let helper = Self {
            path: directory.join("macluster-power"),
            directory,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o700)
            .open(&helper.path)?;
        file.write_all(PAYLOAD)?;
        file.sync_all()?;
        Ok(helper)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ExtractedHelper {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn extraction_is_private_matches_payload_and_is_removed_on_drop() {
        let helper = ExtractedHelper::new().unwrap();
        let directory = helper.directory.clone();
        let path = helper.path().to_path_buf();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            sha256_hex(&fs::read(&path).unwrap()).unwrap(),
            digest().unwrap()
        );
        drop(helper);
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn independent_extractions_do_not_share_mutable_files() {
        let first = ExtractedHelper::new().unwrap();
        let second = ExtractedHelper::new().unwrap();
        assert_ne!(first.path(), second.path());
        fs::write(first.path(), b"corrupt").unwrap();
        assert_eq!(
            sha256_hex(&fs::read(second.path()).unwrap()).unwrap(),
            digest().unwrap()
        );
    }
}
