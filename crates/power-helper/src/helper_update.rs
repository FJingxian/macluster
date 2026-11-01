//! Signed, fixed-path updater for the privileged macluster components.

use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use macluster_protocol::{
    framing::sha256_hex,
    helper_update::{HelperComponent, HelperUpdateManifest, verify_manifest},
    identifiers::Id128,
};
use serde::{Deserialize, Serialize};

pub(crate) const TRUST_DIR: &str = "/Library/PrivilegedHelperTools/org.macluster.update";
const TRUST_KEY: &str = "/Library/PrivilegedHelperTools/org.macluster.update/public-key";
const TRUST_CLUSTER: &str = "/Library/PrivilegedHelperTools/org.macluster.update/cluster-id";
const TRUST_SEQUENCE: &str = "/Library/PrivilegedHelperTools/org.macluster.update/sequence";
const TRUST_LOCK: &str = "/Library/PrivilegedHelperTools/org.macluster.update/update.lock";
const UPDATE_JOURNAL: &str = "/Library/PrivilegedHelperTools/org.macluster.update/transaction.json";
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 768 * 1024 * 1024;
const POWER_HELPER: &str = "/Library/PrivilegedHelperTools/org.macluster.power";
const POWER_REVISION: &str = "/Library/PrivilegedHelperTools/org.macluster.update/power.revision";
const ADMIN_CLI: &str = "/Library/PrivilegedHelperTools/org.macluster.nfs-admin";
const ADMIN_REVISION: &str = "/Library/PrivilegedHelperTools/org.macluster.nfs-admin.version";
const RECOVERY_ROOT: &str = "/Library/PrivilegedHelperTools/org.macluster.nfs";

#[derive(Deserialize)]
struct RecoveryManifest {
    target: PathBuf,
    uuid: String,
    execution_uid: u32,
}

struct Replacement {
    destination: PathBuf,
    source: Option<PathBuf>,
    bytes: Vec<u8>,
    mode: u32,
}

#[derive(Deserialize, Serialize)]
struct UpdateJournal {
    version: u16,
    entries: Vec<UpdateJournalEntry>,
}

#[derive(Deserialize, Serialize)]
struct UpdateJournalEntry {
    destination: String,
    temporary: String,
    backup: String,
    backup_temporary: String,
    had_previous: bool,
}

/// Verify and install a complete signed update. The return value says the
/// serving LaunchDaemon must exit after writing the response so launchd starts
/// the newly installed power helper.
pub(crate) fn apply(
    peer_uid: u32,
    manifest_bytes: &[u8],
    signature: &[u8],
    stage_dir: &str,
) -> Result<bool, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("helper updater must run as root".into());
    }
    let _lock = acquire_update_lock()?;
    recover_interrupted_update()?;
    let cluster_id = read_trusted_text(TRUST_CLUSTER)?;
    let public_key = read_trusted_key()?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "helper update signature must contain exactly 64 bytes".to_owned())?;
    let manifest = verify_manifest(&cluster_id, &public_key, manifest_bytes, &signature)?;
    let current_sequence = read_sequence()?;
    if manifest.sequence <= current_sequence {
        return Err(format!(
            "helper update sequence {} is not newer than installed sequence {current_sequence}",
            manifest.sequence
        ));
    }
    if normalize_arch(&manifest.architecture)? != normalize_arch(std::env::consts::ARCH)? {
        return Err(format!(
            "helper update targets {}, but this Mac is {}",
            manifest.architecture,
            std::env::consts::ARCH
        ));
    }

    let staged = prepare_payloads(peer_uid, stage_dir, &manifest)?;
    let mut replacements = Vec::new();
    let mut recovery_labels = Vec::new();
    let mut restart_power = false;
    for artifact in &manifest.artifacts {
        let payload = staged
            .get(&artifact.stage_name)
            .ok_or_else(|| "verified helper payload disappeared".to_owned())?;
        match &artifact.component {
            HelperComponent::PowerSampler => {
                verify_revision_not_downgraded(
                    read_optional_revision(Path::new(POWER_REVISION))?.as_deref(),
                    &artifact.revision,
                    "power",
                )?;
                replacements.push(Replacement {
                    destination: PathBuf::from(POWER_HELPER),
                    source: Some(payload.clone()),
                    bytes: Vec::new(),
                    mode: 0o755,
                });
                replacements.push(Replacement {
                    destination: PathBuf::from(POWER_REVISION),
                    source: None,
                    bytes: artifact.revision.as_bytes().to_vec(),
                    mode: 0o600,
                });
                restart_power = true;
            }
            HelperComponent::NfsAdminCli => {
                verify_revision_not_downgraded(
                    read_optional_revision(Path::new(ADMIN_REVISION))?.as_deref(),
                    &artifact.revision,
                    "nfs-admin",
                )?;
                replacements.push(Replacement {
                    destination: PathBuf::from(ADMIN_CLI),
                    source: Some(payload.clone()),
                    bytes: Vec::new(),
                    mode: 0o755,
                });
                replacements.push(Replacement {
                    destination: PathBuf::from(ADMIN_REVISION),
                    source: None,
                    bytes: format!("{}\n", artifact.revision).into_bytes(),
                    mode: 0o644,
                });
            }
            HelperComponent::NfsRecovery { target, share_uuid } => {
                let dir = recovery_directory(target)?;
                verify_managed_recovery(&dir, target, share_uuid, peer_uid)?;
                verify_revision_not_downgraded(
                    read_optional_revision(&dir.join("version"))?.as_deref(),
                    &artifact.revision,
                    "nfs-recovery",
                )?;
                replacements.push(Replacement {
                    destination: dir.join("macluster"),
                    source: Some(payload.clone()),
                    bytes: Vec::new(),
                    mode: 0o700,
                });
                replacements.push(Replacement {
                    destination: dir.join("version"),
                    source: None,
                    bytes: format!("{}\n", artifact.revision).into_bytes(),
                    mode: 0o644,
                });
                recovery_labels.push(recovery_label(target)?);
            }
        }
    }

    let operation_id = stage_id(stage_dir)?;
    replacements.push(Replacement {
        destination: PathBuf::from(TRUST_SEQUENCE),
        source: None,
        bytes: format!("{}\n", manifest.sequence).into_bytes(),
        mode: 0o600,
    });
    let journal = plan_update(&replacements, &operation_id)?;
    write_update_journal(&journal, &operation_id)?;
    let result = (|| {
        for (replacement, entry) in replacements.iter().zip(&journal.entries) {
            apply_replacement(replacement, entry)?;
        }
        for label in &recovery_labels {
            restart_service(label)?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let rollback = recover_interrupted_update();
        cleanup_payloads(&staged);
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(format!(
                "helper update failed: {error}; rollback is incomplete: {rollback_error}"
            )),
        };
    }
    finish_update_journal(&journal)?;
    cleanup_payloads(&staged);
    Ok(restart_power)
}

/// Remove the trust record for a cluster that has explicitly removed this node
/// or reset the cluster. This operation is intentionally scoped to the pinned
/// cluster ID and never removes the installed NFS or power services.
pub(crate) fn forget_cluster(peer_uid: u32, requested_cluster_id: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("helper trust removal must run as root".into());
    }
    if peer_uid == 0 {
        return Err("helper trust removal requires a non-root cluster account".into());
    }
    let parsed = Id128::parse(requested_cluster_id)
        .map_err(|_| "cluster updater identity is invalid".to_owned())?;
    if parsed.to_string() != requested_cluster_id {
        return Err("cluster updater identity must be canonical".into());
    }
    let trust_dir = Path::new(TRUST_DIR);
    match fs::symlink_metadata(trust_dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("inspect pinned cluster updater state: {error}")),
        Ok(_) => {}
    }
    verify_root_directory(trust_dir)?;
    let _lock = acquire_update_lock()?;
    recover_interrupted_update()?;
    let installed_cluster_id = read_trusted_text(TRUST_CLUSTER)?;
    if installed_cluster_id != requested_cluster_id {
        return Err("refusing to forget updater trust for a different cluster".into());
    }

    let entries = fs::read_dir(trust_dir)
        .map_err(|error| format!("list pinned cluster updater state: {error}"))?;
    let names = entries
        .map(|entry| {
            entry
                .map_err(|error| format!("list pinned cluster updater state: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "pinned updater state contains a non-UTF-8 filename".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let names = validated_trust_entry_names(names)?;
    let mut paths = Vec::with_capacity(names.len());
    for name in names {
        let path = trust_dir.join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect pinned updater state {}: {error}", path.display()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "pinned updater state {} has unsafe ownership or type",
                path.display()
            ));
        }
        paths.push(path);
    }
    // Validate the complete directory before deleting any part of the trust
    // state, so an unexpected entry cannot cause a partially completed removal.
    for path in paths {
        fs::remove_file(&path)
            .map_err(|error| format!("remove pinned updater state {}: {error}", path.display()))?;
    }
    fs::remove_dir(trust_dir)
        .map_err(|error| format!("remove pinned updater directory: {error}"))?;
    File::open(
        Path::new(TRUST_DIR)
            .parent()
            .expect("trust directory has parent"),
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| format!("sync pinned updater directory removal: {error}"))?;
    Ok(())
}

fn managed_trust_entry(name: &str) -> bool {
    if matches!(
        name,
        "public-key"
            | "cluster-id"
            | "sequence"
            | "update.lock"
            | "transaction.json"
            | "power.revision"
            | "nfs-admin.revision"
    ) {
        return true;
    }
    if let Some(operation_id) = name
        .strip_prefix(".transaction-")
        .and_then(|value| value.strip_suffix(".next"))
    {
        return Id128::parse(operation_id).is_ok();
    }
    if managed_update_transaction_entry(name) {
        return true;
    }
    let Some(payload) = name.strip_prefix("payload-") else {
        return false;
    };
    if payload.len() <= 37 || payload.as_bytes().get(36) != Some(&b'-') {
        return false;
    }
    let operation_id = &payload[..36];
    let stage_name = &payload[37..];
    Id128::parse(operation_id).is_ok()
        && !stage_name.is_empty()
        && stage_name.len() <= 96
        && stage_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn managed_update_transaction_entry(name: &str) -> bool {
    let Some(entry) = name.strip_prefix(".macluster-update-") else {
        return false;
    };
    let Some((operation_and_index, suffix)) = entry.rsplit_once('.') else {
        return false;
    };
    if !matches!(suffix, "next" | "previous" | "previous-next") {
        return false;
    }
    let Some((operation_id, encoded_index)) = operation_and_index.rsplit_once('-') else {
        return false;
    };
    let Ok(operation_id_value) = Id128::parse(operation_id) else {
        return false;
    };
    let Ok(index) = encoded_index.parse::<usize>() else {
        return false;
    };
    operation_id_value.to_string() == operation_id
        && index < 1024
        && index.to_string() == encoded_index
}

fn validated_trust_entry_names(
    names: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, String> {
    let mut validated = Vec::new();
    for name in names {
        if !managed_trust_entry(&name) {
            return Err(format!(
                "refusing to remove unknown pinned updater state {name}"
            ));
        }
        validated.push(name);
    }
    // Keep the cluster identity marker until all other removals have succeeded,
    // so a transient filesystem error can be retried safely.
    validated.sort_by_key(|name| name == "cluster-id");
    Ok(validated)
}

fn prepare_payloads(
    peer_uid: u32,
    stage_dir: &str,
    manifest: &HelperUpdateManifest,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut payloads = BTreeMap::new();
    let result = (|| {
        let mut total_bytes = 0_u64;
        for artifact in &manifest.artifacts {
            if payloads.contains_key(&artifact.stage_name) {
                continue;
            }
            let bytes = read_stage_file(peer_uid, stage_dir, &artifact.stage_name)?;
            total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            if bytes.len() as u64 > MAX_ARTIFACT_BYTES || total_bytes > MAX_TOTAL_BYTES {
                return Err("helper update payload exceeds the size limit".into());
            }
            let digest = sha256_hex(&bytes).map_err(|error| error.to_string())?;
            if digest != artifact.sha256 {
                return Err(format!(
                    "helper artifact {} checksum does not match the signed manifest",
                    artifact.stage_name
                ));
            }
            let name = format!("payload-{}-{}", stage_id(stage_dir)?, artifact.stage_name);
            let path = Path::new(TRUST_DIR).join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|error| format!("stage verified helper payload: {error}"))?;
            if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
                let _ = fs::remove_file(&path);
                return Err(format!("write verified helper payload: {error}"));
            }
            drop(file);
            if let Err(error) = inspect_architecture(&path, &manifest.architecture) {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            payloads.insert(artifact.stage_name.clone(), path);
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        cleanup_payloads(&payloads);
        return Err(error);
    }
    Ok(payloads)
}

fn read_stage_file(peer_uid: u32, stage_dir: &str, name: &str) -> Result<Vec<u8>, String> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("helper artifact has an unsafe stage name".into());
    }
    let stage = stage_id(stage_dir)?;
    let tmp = CString::new("/tmp").expect("literal has no NUL");
    let directory =
        CString::new(format!("macluster-update-{stage}")).map_err(|error| error.to_string())?;
    let file_name = CString::new(name).map_err(|error| error.to_string())?;
    let tmp_fd = unsafe { libc::open(tmp.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if tmp_fd < 0 {
        return Err(format!(
            "open temporary directory: {}",
            io::Error::last_os_error()
        ));
    }
    let tmp_file = unsafe { File::from_raw_fd(tmp_fd) };
    let dir_fd = unsafe {
        libc::openat(
            tmp_file.as_raw_fd(),
            directory.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if dir_fd < 0 {
        return Err(format!(
            "open helper staging directory: {}",
            io::Error::last_os_error()
        ));
    }
    let dir = unsafe { File::from_raw_fd(dir_fd) };
    let dir_meta = dir.metadata().map_err(io_error)?;
    if !dir_meta.is_dir() || dir_meta.uid() != peer_uid || dir_meta.mode() & 0o077 != 0 {
        return Err(
            "helper staging directory must be owned by the cluster account with mode 0700".into(),
        );
    }
    let file_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )
    };
    if file_fd < 0 {
        return Err(format!(
            "open staged helper artifact: {}",
            io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(file_fd) };
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.uid() != peer_uid || metadata.len() > MAX_ARTIFACT_BYTES {
        return Err("staged helper artifact has unsafe ownership, type, or size".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err("staged helper artifact changed while being read".into());
    }
    Ok(bytes)
}

fn inspect_architecture(path: &Path, expected: &str) -> Result<(), String> {
    let output = Command::new("/usr/bin/lipo")
        .args(["-archs"])
        .arg(path)
        .output()
        .map_err(|error| format!("inspect helper architecture: {error}"))?;
    let arch = normalize_arch(expected)?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .any(|item| item == arch)
    {
        return Err(format!(
            "helper artifact does not contain the {arch} architecture"
        ));
    }
    Ok(())
}

fn normalize_arch(value: &str) -> Result<&'static str, String> {
    match value {
        "arm64" | "aarch64" => Ok("arm64"),
        "x86_64" => Ok("x86_64"),
        _ => Err(format!("unsupported helper architecture '{value}'")),
    }
}

fn recovery_directory(target: &str) -> Result<PathBuf, String> {
    let digest = sha256_hex(target.as_bytes()).map_err(|error| error.to_string())?;
    Ok(Path::new(RECOVERY_ROOT).join(digest))
}

fn recovery_label(target: &str) -> Result<String, String> {
    let digest = sha256_hex(target.as_bytes()).map_err(|error| error.to_string())?;
    Ok(format!("org.macluster.nfs.{digest}"))
}

fn verify_managed_recovery(
    directory: &Path,
    target: &str,
    share_uuid: &str,
    peer_uid: u32,
) -> Result<(), String> {
    verify_root_directory(directory)?;
    let manifest_path = directory.join("manifest.json");
    let bytes = read_root_file(&manifest_path, 1024 * 1024)?;
    let manifest: RecoveryManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid managed NFS recovery manifest: {error}"))?;
    if manifest.target != Path::new(target)
        || manifest.uuid != share_uuid
        || manifest.execution_uid != peer_uid
    {
        return Err(format!(
            "NFS recovery service for {target} does not match the signed share identity"
        ));
    }
    Ok(())
}

fn plan_update(replacements: &[Replacement], operation_id: &str) -> Result<UpdateJournal, String> {
    let mut entries = Vec::with_capacity(replacements.len());
    for (index, replacement) in replacements.iter().enumerate() {
        let destination = &replacement.destination;
        let parent = destination
            .parent()
            .ok_or_else(|| "helper destination has no parent".to_owned())?;
        verify_root_directory(parent)?;
        if !allowed_destination(destination) {
            return Err(format!(
                "helper destination {} is not allowlisted",
                destination.display()
            ));
        }
        let had_previous = match fs::symlink_metadata(destination) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0 =>
            {
                true
            }
            Ok(_) => {
                return Err(format!(
                    "refusing to replace unsafe helper destination {}",
                    destination.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!("inspect {}: {error}", destination.display()));
            }
        };
        let prefix = format!(".macluster-update-{operation_id}-{index}");
        let temporary = parent.join(format!("{prefix}.next"));
        let backup = parent.join(format!("{prefix}.previous"));
        let backup_temporary = parent.join(format!("{prefix}.previous-next"));
        for path in [&temporary, &backup, &backup_temporary] {
            if fs::symlink_metadata(path).is_ok() {
                return Err(format!(
                    "stale helper transaction file {} exists",
                    path.display()
                ));
            }
        }
        entries.push(UpdateJournalEntry {
            destination: destination.to_string_lossy().into_owned(),
            temporary: temporary.to_string_lossy().into_owned(),
            backup: backup.to_string_lossy().into_owned(),
            backup_temporary: backup_temporary.to_string_lossy().into_owned(),
            had_previous,
        });
    }
    Ok(UpdateJournal {
        version: 1,
        entries,
    })
}

fn write_update_journal(journal: &UpdateJournal, operation_id: &str) -> Result<(), String> {
    let temporary = Path::new(TRUST_DIR).join(format!(".transaction-{operation_id}.next"));
    let bytes = serde_json::to_vec(journal).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("stage helper update journal: {error}"))?;
    if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("write helper update journal: {error}"));
    }
    drop(file);
    fs::rename(&temporary, UPDATE_JOURNAL)
        .map_err(|error| format!("commit helper update journal: {error}"))?;
    File::open(TRUST_DIR)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync helper update journal: {error}"))
}

fn apply_replacement(replacement: &Replacement, entry: &UpdateJournalEntry) -> Result<(), String> {
    let destination = PathBuf::from(&entry.destination);
    let temporary = PathBuf::from(&entry.temporary);
    let backup = PathBuf::from(&entry.backup);
    let backup_temporary = PathBuf::from(&entry.backup_temporary);
    if destination != replacement.destination
        || !allowed_destination(&destination)
        || temporary.parent() != destination.parent()
        || backup.parent() != destination.parent()
        || backup_temporary.parent() != destination.parent()
    {
        return Err("helper update journal paths do not match the replacement plan".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(replacement.mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("stage {}: {error}", destination.display()))?;
    let write_result = if let Some(source) = &replacement.source {
        let metadata = fs::symlink_metadata(source)
            .map_err(|error| format!("inspect verified helper payload: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            let _ = fs::remove_file(&temporary);
            return Err("verified helper payload has unsafe ownership or type".into());
        }
        let mut input = File::open(source).map_err(io_error)?;
        io::copy(&mut input, &mut output).and_then(|_| output.sync_all())
    } else {
        output
            .write_all(&replacement.bytes)
            .and_then(|_| output.sync_all())
    };
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(format!("write {}: {error}", destination.display()));
    }
    drop(output);

    if entry.had_previous {
        let metadata = fs::symlink_metadata(&destination).map_err(|error| {
            format!(
                "inspect {} before replacement: {error}",
                destination.display()
            )
        })?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            let _ = fs::remove_file(&temporary);
            return Err(format!(
                "refusing to back up unsafe helper destination {}",
                destination.display()
            ));
        }
        let mut source = File::open(&destination).map_err(io_error)?;
        let mut backup_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(metadata.mode() & 0o777)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&backup_temporary)
            .map_err(|error| format!("stage rollback copy: {error}"))?;
        if let Err(error) =
            io::copy(&mut source, &mut backup_file).and_then(|_| backup_file.sync_all())
        {
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_file(&backup_temporary);
            return Err(format!(
                "preserve {} for rollback: {error}",
                destination.display()
            ));
        }
        drop(backup_file);
        fs::rename(&backup_temporary, &backup)
            .map_err(|error| format!("commit rollback copy: {error}"))?;
    } else if fs::symlink_metadata(&destination).is_ok() {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "helper destination {} appeared during update",
            destination.display()
        ));
    }
    fs::rename(&temporary, &destination)
        .map_err(|error| format!("install {}: {error}", destination.display()))?;
    if let Some(parent) = destination.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync {}: {error}", parent.display()))?;
    }
    Ok(())
}

fn recover_interrupted_update() -> Result<(), String> {
    let bytes = match read_root_file(Path::new(UPDATE_JOURNAL), 1024 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.contains("No such file") => return Ok(()),
        Err(error) => return Err(error),
    };
    let journal: UpdateJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("helper update journal is malformed: {error}"))?;
    if journal.version != 1 || journal.entries.is_empty() || journal.entries.len() > 1024 {
        return Err("helper update journal has an unsupported version or size".into());
    }
    let mut restart_labels = BTreeMap::new();
    for entry in journal.entries.iter().rev() {
        let destination = PathBuf::from(&entry.destination);
        let temporary = PathBuf::from(&entry.temporary);
        let backup = PathBuf::from(&entry.backup);
        let backup_temporary = PathBuf::from(&entry.backup_temporary);
        if !allowed_destination(&destination)
            || temporary.parent() != destination.parent()
            || backup.parent() != destination.parent()
            || backup_temporary.parent() != destination.parent()
            || !transaction_path_name(&temporary)
            || !transaction_path_name(&backup)
            || !transaction_path_name(&backup_temporary)
        {
            return Err("helper update journal contains an unsafe path".into());
        }
        if entry.had_previous {
            match fs::symlink_metadata(&backup) {
                Ok(metadata)
                    if metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == 0
                        && metadata.mode() & 0o022 == 0 =>
                {
                    fs::rename(&backup, &destination).map_err(|error| {
                        format!("restore previous helper {}: {error}", destination.display())
                    })?;
                }
                Ok(_) => return Err(format!("unsafe rollback copy {}", backup.display())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("inspect rollback copy: {error}")),
            }
        } else {
            match fs::symlink_metadata(&destination) {
                Ok(metadata)
                    if metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == 0
                        && metadata.mode() & 0o022 == 0 =>
                {
                    fs::remove_file(&destination).map_err(|error| {
                        format!(
                            "remove incomplete helper {}: {error}",
                            destination.display()
                        )
                    })?;
                }
                Ok(_) => {
                    return Err(format!(
                        "unsafe incomplete helper {}",
                        destination.display()
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("inspect incomplete helper: {error}")),
            }
        }
        for path in [&temporary, &backup, &backup_temporary] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("clean helper transaction file: {error}")),
            }
        }
        if let Some(label) = recovery_service_for_destination(&destination) {
            restart_labels.insert(label.clone(), label);
        }
    }
    fs::remove_file(UPDATE_JOURNAL)
        .map_err(|error| format!("remove recovered helper update journal: {error}"))?;
    File::open(TRUST_DIR)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync recovered helper update journal: {error}"))?;
    for label in restart_labels.keys() {
        let _ = restart_service(label);
    }
    Ok(())
}

fn finish_update_journal(journal: &UpdateJournal) -> Result<(), String> {
    fs::remove_file(UPDATE_JOURNAL)
        .map_err(|error| format!("remove committed helper update journal: {error}"))?;
    File::open(TRUST_DIR)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync committed helper update journal: {error}"))?;
    for entry in &journal.entries {
        for path in [
            PathBuf::from(&entry.temporary),
            PathBuf::from(&entry.backup),
            PathBuf::from(&entry.backup_temporary),
        ] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("clean helper transaction file: {error}")),
            }
        }
    }
    Ok(())
}

fn allowed_destination(path: &Path) -> bool {
    if [
        POWER_HELPER,
        POWER_REVISION,
        ADMIN_CLI,
        ADMIN_REVISION,
        TRUST_SEQUENCE,
    ]
    .into_iter()
    .any(|value| path == Path::new(value))
    {
        return true;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(root) = parent.parent() else {
        return false;
    };
    root == Path::new(RECOVERY_ROOT)
        && parent
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        && matches!(
            path.file_name().and_then(|value| value.to_str()),
            Some("macluster" | "version")
        )
}

fn transaction_path_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.starts_with(".macluster-update-") && !name.contains('/'))
}

fn recovery_service_for_destination(path: &Path) -> Option<String> {
    if path.file_name().and_then(|value| value.to_str()) != Some("macluster") {
        return None;
    }
    let parent = path.parent()?;
    let root = parent.parent()?;
    if root != Path::new(RECOVERY_ROOT) {
        return None;
    }
    let digest = parent.file_name()?.to_str()?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("org.macluster.nfs.{digest}"))
}

fn cleanup_payloads(payloads: &BTreeMap<String, PathBuf>) {
    for path in payloads.values() {
        let _ = fs::remove_file(path);
    }
}

fn restart_service(label: &str) -> Result<(), String> {
    if !label.starts_with("org.macluster.nfs.")
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        return Err("invalid managed recovery service label".into());
    }
    let output = Command::new("/bin/launchctl")
        .args(["kickstart", "-k", &format!("system/{label}")])
        .output()
        .map_err(|error| format!("restart NFS recovery service {label}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "restart NFS recovery service {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn read_trusted_text(path: &str) -> Result<String, String> {
    let value = String::from_utf8(read_root_file(Path::new(path), 256)?)
        .map_err(|error| format!("trusted updater identity is not UTF-8: {error}"))?;
    let value = value.trim_end_matches('\n');
    Id128::parse(value).map_err(|_| "trusted updater cluster ID is invalid".to_owned())?;
    Ok(value.to_owned())
}

fn read_trusted_key() -> Result<[u8; 32], String> {
    let bytes = read_root_file(Path::new(TRUST_KEY), 32)?;
    bytes
        .try_into()
        .map_err(|_| "trusted updater public key must contain exactly 32 bytes".to_owned())
}

fn read_sequence() -> Result<u64, String> {
    let path = Path::new(TRUST_SEQUENCE);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("inspect helper update sequence: {error}")),
    };
    validate_root_file_metadata(path, &metadata, 64)?;
    String::from_utf8(fs::read(path).map_err(io_error)?)
        .map_err(|error| format!("invalid helper update sequence: {error}"))?
        .trim()
        .parse()
        .map_err(|_| "invalid helper update sequence".to_owned())
}

fn read_optional_revision(path: &Path) -> Result<Option<String>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect component revision {}: {error}",
                path.display()
            ));
        }
    };
    validate_root_file_metadata(path, &metadata, 256)?;
    String::from_utf8(fs::read(path).map_err(io_error)?)
        .map(|value| Some(value.trim().to_owned()))
        .map_err(|error| format!("helper component revision is not UTF-8: {error}"))
}

fn verify_revision_not_downgraded(
    current: Option<&str>,
    requested: &str,
    prefix: &str,
) -> Result<(), String> {
    let parse = |value: &str| {
        value
            .strip_prefix(&format!("{prefix}-"))
            .and_then(|number| number.parse::<u64>().ok())
    };
    let requested_number = parse(requested)
        .ok_or_else(|| format!("invalid {prefix} component revision '{requested}'"))?;
    if let Some(current) = current {
        let current_number = parse(current)
            .ok_or_else(|| format!("installed {prefix} component revision is invalid"))?;
        if requested_number < current_number {
            return Err(format!(
                "refusing {prefix} downgrade from {current} to {requested}"
            ));
        }
    }
    Ok(())
}

fn read_root_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect trusted updater file {}: {error}", path.display()))?;
    validate_root_file_metadata(path, &metadata, maximum)?;
    fs::read(path).map_err(|error| format!("read trusted updater file {}: {error}", path.display()))
}

fn validate_root_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    maximum: u64,
) -> Result<(), String> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "trusted updater file {} has unsafe ownership, type, or size",
            path.display()
        ));
    }
    Ok(())
}

fn verify_root_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "inspect trusted helper directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "trusted helper directory {} has unsafe ownership or permissions",
            path.display()
        ));
    }
    Ok(())
}

fn acquire_update_lock() -> Result<File, String> {
    verify_root_directory(Path::new(TRUST_DIR))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(TRUST_LOCK)
        .map_err(|error| format!("open helper updater lock: {error}"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "another helper update is active: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn stage_id(stage_dir: &str) -> Result<String, String> {
    let value = stage_dir
        .strip_prefix("/tmp/macluster-update-")
        .ok_or_else(|| "helper update stage directory is invalid".to_owned())?;
    let id =
        Id128::parse(value).map_err(|_| "helper update stage directory is invalid".to_owned())?;
    Ok(id.to_string())
}

fn io_error(error: io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use super::{normalize_arch, read_stage_file, stage_id, verify_revision_not_downgraded};
    use macluster_protocol::identifiers::Id128;

    #[test]
    fn update_stage_directory_requires_a_canonical_operation_uuid() {
        assert_eq!(
            stage_id("/tmp/macluster-update-00000000-0000-4000-8000-000000000001").unwrap(),
            "00000000-0000-4000-8000-000000000001"
        );
        assert!(stage_id("/tmp/macluster-update-../../etc").is_err());
        assert!(
            stage_id("/tmp/macluster-update-00000000-0000-4000-8000-000000000001/extra").is_err()
        );
    }

    #[test]
    fn trust_cleanup_accepts_only_managed_root_state_names() {
        use super::{managed_trust_entry, validated_trust_entry_names};

        let operation = "00000000-0000-4000-8000-000000000001";
        assert!(managed_trust_entry("public-key"));
        assert!(managed_trust_entry("transaction.json"));
        assert!(managed_trust_entry(&format!(
            ".transaction-{operation}.next"
        )));
        for suffix in ["next", "previous", "previous-next"] {
            assert!(managed_trust_entry(&format!(
                ".macluster-update-{operation}-12.{suffix}"
            )));
        }
        assert!(managed_trust_entry(&format!(
            "payload-{operation}-payload-{}",
            "a".repeat(64)
        )));
        assert!(!managed_trust_entry(&format!(
            ".macluster-update-{operation}-x.next"
        )));
        assert!(!managed_trust_entry(&format!(
            ".macluster-update-{operation}-12.unknown"
        )));
        assert!(!managed_trust_entry("payload-not-an-operation-id-bin"));
        assert!(!managed_trust_entry("unknown"));
        assert!(!managed_trust_entry("../public-key"));
        assert_eq!(
            validated_trust_entry_names(vec!["cluster-id".into(), "public-key".into()]).unwrap(),
            ["public-key", "cluster-id"]
        );
        assert!(validated_trust_entry_names(vec!["public-key".into(), "unknown".into()]).is_err());
    }

    #[test]
    fn only_supported_macos_architectures_are_accepted() {
        assert_eq!(normalize_arch("aarch64").unwrap(), "arm64");
        assert_eq!(normalize_arch("x86_64").unwrap(), "x86_64");
        assert!(normalize_arch("i386").is_err());
    }

    #[test]
    fn component_revisions_reject_downgrades_and_malformed_values() {
        assert!(verify_revision_not_downgraded(Some("power-4"), "power-4", "power").is_ok());
        assert!(verify_revision_not_downgraded(Some("power-4"), "power-5", "power").is_ok());
        assert!(verify_revision_not_downgraded(Some("power-4"), "power-3", "power").is_err());
        assert!(verify_revision_not_downgraded(None, "power-invalid", "power").is_err());
    }

    #[test]
    fn stage_reader_accepts_only_account_owned_regular_files_without_symlink_following() {
        let operation_id = Id128::random().to_string();
        let stage_dir = format!("/tmp/macluster-update-{operation_id}");
        fs::create_dir(&stage_dir).unwrap();
        fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let payload = Path::new(&stage_dir).join("payload.bin");
        fs::write(&payload, b"payload").unwrap();
        assert_eq!(
            read_stage_file(unsafe { libc::geteuid() }, &stage_dir, "payload.bin").unwrap(),
            b"payload"
        );

        let link = Path::new(&stage_dir).join("linked.bin");
        std::os::unix::fs::symlink(&payload, &link).unwrap();
        assert!(read_stage_file(unsafe { libc::geteuid() }, &stage_dir, "linked.bin").is_err());
        assert!(read_stage_file(unsafe { libc::geteuid() }, &stage_dir, "../outside").is_err());
        fs::remove_dir_all(stage_dir).unwrap();
    }
}
