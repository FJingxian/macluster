//! Privileged, narrowly scoped recovery of approved NFS mounts after boot.
use crate::node_admin::{NamedShareMountStatus, named_share_mount_status};
use macluster_protocol::{framing::sha256_hex, identifiers::Id128};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/Library/PrivilegedHelperTools/org.macluster.nfs";
// Privileged service release version, independent of the Agent build. Bump
// whenever recovery behavior or its runtime dependencies change (including
// named_share_mount_status and run_child_bounded). Comments/tests need no bump.
const SERVICE_VERSION: &str = "nfs-recovery-7";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
// One recovery attempt can run five bounded child commands. Leave margin for
// process termination and lock handoff before install/remove gives up.
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Manifest {
    source: String,
    target: PathBuf,
    uuid: String,
    execution_uid: u32,
    #[serde(default)]
    allow_existing_contents: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct Status {
    failures: u32,
    retry_after: u64,
    error: Option<String>,
}
fn key(target: &Path) -> String {
    sha256_hex(target.as_os_str().as_encoded_bytes()).expect("SHA256")
}
fn directory(target: &Path) -> PathBuf {
    Path::new(ROOT).join(key(target))
}
pub(crate) fn version_marker_path(target: &Path) -> PathBuf {
    directory(target).join("version")
}
pub(crate) fn helper_version() -> String {
    SERVICE_VERSION.to_owned()
}
pub(crate) fn installation_probe_script(target: &Path) -> String {
    installation_check_script(
        &directory(target),
        &plist_path(target),
        &format!("system/{}", label(target)),
        Path::new("/bin/launchctl"),
    )
}

fn installation_check_script(dir: &Path, plist: &Path, service: &str, launchctl: &Path) -> String {
    let mut checks = Vec::new();
    for file in [
        dir.join("macluster"),
        dir.join("manifest.json"),
        dir.join("version"),
        plist.to_owned(),
    ] {
        let path = quote(&file.to_string_lossy());
        checks.push(format!("[ -f {path} ] && [ ! -L {path} ] && [ -s {path} ]"));
    }
    checks.push(format!(
        "[ \"$(/bin/cat {} 2>/dev/null)\" = {} ]",
        quote(&dir.join("version").to_string_lossy()),
        quote(SERVICE_VERSION)
    ));
    checks.push(format!(
        "{} print {} >/dev/null 2>&1",
        quote(&launchctl.to_string_lossy()),
        quote(service)
    ));
    checks.join(" && ")
}
fn label(target: &Path) -> String {
    format!("org.macluster.nfs.{}", key(target))
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub(crate) fn install_script(
    binary: &str,
    source: &str,
    target: &Path,
    uuid: &str,
    execution_uid: Option<u32>,
    allow_existing_contents: bool,
) -> String {
    let dir = quote(&directory(target).to_string_lossy());
    let uid = execution_uid
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| "${SUDO_UID:?missing execution UID}".into());
    format!(
        "[ ! -L {root} ] && [ ! -L {dir} ] || {{ echo 'unsafe NFS recovery install path' >&2; exit 1; }}\n/bin/mkdir -p {dir}\n/usr/sbin/chown root:wheel {root}\n/bin/chmod 755 {root}\n/usr/sbin/chown root:wheel {dir}\n/bin/chmod 755 {dir}\n/usr/bin/install -o root -g wheel -m 700 {} {dir}/macluster.next\n/bin/mv -f {dir}/macluster.next {dir}/macluster\n{dir}/macluster internal nfs-recovery install {} {} {} {uid}{}\n",
        quote(binary),
        quote(source),
        quote(&target.to_string_lossy()),
        quote(uuid),
        if allow_existing_contents {
            " --overlay-existing"
        } else {
            ""
        },
        root = quote(ROOT),
    )
}

#[cfg(test)]
pub(crate) fn refresh_script(
    binary: &str,
    binary_digest: &str,
    source: &str,
    target: &Path,
    uuid: &str,
    execution_uid: Option<u32>,
    allow_existing_contents: bool,
) -> String {
    let root = quote(ROOT);
    let dir = quote(&directory(target).to_string_lossy());
    let helper = quote(&directory(target).join("macluster").to_string_lossy());
    let next = quote(&directory(target).join("macluster.next").to_string_lossy());
    let uid = execution_uid
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| "${SUDO_UID:?missing execution UID}".into());
    format!(
        "[ ! -L {root} ] && [ ! -L {dir} ] || {{ echo 'unsafe NFS recovery install path' >&2; exit 1; }}\n/bin/mkdir -p {dir}\n/usr/sbin/chown root:wheel {root}\n/bin/chmod 755 {root}\n/usr/sbin/chown root:wheel {dir}\n/bin/chmod 755 {dir}\nif [ ! -f {} ] || [ -L {} ]; then echo 'NFS recovery source binary is not a regular file' >&2; exit 1; fi\nactual=$(/usr/bin/shasum -a 256 {})\n[ \"${{actual%% *}}\" = {} ] || {{ echo 'NFS recovery source checksum mismatch' >&2; exit 1; }}\n[ ! -L {next} ] || {{ echo 'unsafe NFS recovery staging path' >&2; exit 1; }}\n/usr/bin/install -o root -g wheel -m 700 {} {next}\nactual=$(/usr/bin/shasum -a 256 {next})\n[ \"${{actual%% *}}\" = {} ] || {{ /bin/rm -f {next}; echo 'NFS recovery staged checksum mismatch' >&2; exit 1; }}\n/bin/mv -f {next} {helper}\n{helper} internal nfs-recovery refresh {} {} {} {uid}{}\n",
        quote(binary),
        quote(binary),
        quote(binary),
        quote(binary_digest),
        quote(binary),
        quote(binary_digest),
        quote(source),
        quote(&target.to_string_lossy()),
        quote(uuid),
        if allow_existing_contents {
            " --overlay-existing"
        } else {
            ""
        },
    )
}

pub(crate) fn cleanup_script(source: &str, target: &Path, uuid: &str) -> String {
    let helper = quote(&directory(target).join("macluster").to_string_lossy());
    format!(
        "if [ -e {helper} ]; then {helper} internal nfs-recovery remove {} {} {}; fi\n",
        quote(source),
        quote(&target.to_string_lossy()),
        quote(uuid)
    )
}
fn valid_target(target: &Path) -> Result<(), String> {
    if !target.is_absolute()
        || target == Path::new("/")
        || target
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        || target.to_string_lossy().contains(['\n', '\r'])
    {
        return Err("invalid recovery mount path".into());
    }
    Ok(())
}
fn secure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(format!("unsafe recovery directory {}", path.display()));
    }
    Ok(())
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temp = path.with_extension("next");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    f.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(temp, path).map_err(|e| e.to_string())
}
fn bounded(program: &str, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args);
    bounded_command(command)
}
fn bounded_as_user(program: &str, args: &[&str], uid: u32) -> Result<String, String> {
    let output = bounded_as_user_output(program, args, uid)?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn bounded_as_user_output(
    program: &str,
    args: &[&str],
    uid: u32,
) -> Result<std::process::Output, String> {
    use std::os::unix::process::CommandExt;
    if uid == 0 {
        return Err("NFS recovery requires a non-root execution UID".into());
    }
    let account = unsafe { libc::getpwuid(uid) };
    if account.is_null() {
        return Err("NFS recovery execution account no longer exists".into());
    }
    let gid = unsafe { (*account).pw_gid };
    let mut command = Command::new(program);
    command.args(args).gid(gid).uid(uid);
    bounded_command_output(command).map_err(|error| {
        format!(
            "{} {}: {error}",
            program,
            args.iter()
                .map(|argument| quote(argument))
                .collect::<Vec<_>>()
                .join(" ")
        )
    })
}
fn bounded_command(command: Command) -> Result<String, String> {
    let out = bounded_command_output(command)?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
fn bounded_command_output(command: Command) -> Result<std::process::Output, String> {
    macluster_controller::transport::run_child_bounded(command, None, COMMAND_TIMEOUT)
        .map_err(|error| error.to_string())
}
fn mount_table() -> Result<String, String> {
    bounded("/sbin/mount", &[])
}
fn expected(source: &str, target: &Path, mounts: &str) -> Result<bool, String> {
    match named_share_mount_status(mounts, source, &target.to_string_lossy()) {
        NamedShareMountStatus::Expected => Ok(true),
        NamedShareMountStatus::NotMounted => Ok(false),
        NamedShareMountStatus::MountedElsewhere(other) => {
            Err(format!("mount conflict at {}: {other}", target.display()))
        }
    }
}
fn nfs_mount_is_not_responding(output: &str, target: &Path) -> bool {
    let prefix = format!("{} from ", target.display());
    let mut in_target = false;
    for line in output.lines() {
        if line.contains(" from ") {
            in_target = line.starts_with(&prefix);
        } else if in_target && line.contains("Status flags:") {
            return line.contains("not responding");
        }
    }
    false
}
fn ensure_mount(
    source: &str,
    target: &Path,
    allow_existing_contents: bool,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<(), String> {
    let mounts = execute("/sbin/mount", &[])?;
    if expected(source, target, &mounts)? {
        return Ok(());
    }
    safe_mount_target(target, allow_existing_contents)?;
    let attempt = execute(
        "/sbin/mount_nfs",
        &["-o", "resvport", source, &target.to_string_lossy()],
    );
    if let Err(error) = attempt {
        if !is_mount_busy_error(&error) {
            return Err(error);
        }

        // The kernel may retain a stale vnode for an empty, unmounted local
        // mountpoint after an earlier NFS failure. Only repair that narrow
        // case; never remove a mount, local data, or a directory in use.
        if expected(source, target, &execute("/sbin/mount", &[])?)? {
            return Ok(());
        }
        recreate_empty_mountpoint(source, target, execute)?;
        if expected(source, target, &execute("/sbin/mount", &[])?)? {
            return Ok(());
        }
        execute(
            "/sbin/mount_nfs",
            &["-o", "resvport", source, &target.to_string_lossy()],
        )
        .map_err(|retry_error| {
            format!(
                "NFS mount remained busy after safely recreating the empty mountpoint: {retry_error}"
            )
        })?;
    }
    if !expected(source, target, &execute("/sbin/mount", &[])?)? {
        return Err("NFS mount did not appear after recovery".into());
    }
    Ok(())
}
fn is_mount_busy_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    ["resource busy", "device busy", "mount point is busy"]
        .iter()
        .any(|needle| error.contains(needle))
}
fn recreate_empty_mountpoint(
    source: &str,
    target: &Path,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<(), String> {
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};

    // Check again immediately before touching the directory. A mount that
    // appeared since the prior check must be left alone.
    if expected(source, target, &execute("/sbin/mount", &[])?)? {
        return Ok(());
    }
    safe_mount_target(target, true)?;
    let mut entries = fs::read_dir(target).map_err(|error| error.to_string())?;
    if entries
        .next()
        .transpose()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err(format!(
            "cannot repair busy mount point {} because it contains local files; preserving them",
            target.display()
        ));
    }
    // Close the directory descriptor before lsof; otherwise the recovery
    // process would report its own read_dir handle as a user of the path.
    drop(entries);

    let target_arg = target.to_string_lossy();
    match execute("/usr/sbin/lsof", &["-nP", "-t", &target_arg]) {
        Ok(output) if output.trim().is_empty() => {}
        Err(error) if error.trim().is_empty() => {}
        Ok(_) => {
            return Err(format!(
                "cannot repair busy mount point {} because it is in use by a process",
                target.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "cannot verify whether a process is using mount point {}: {error}",
                target.display()
            ));
        }
    }

    let metadata = fs::symlink_metadata(target).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("unsafe mount path {}", target.display()));
    }
    let parent = target
        .parent()
        .ok_or_else(|| format!("mount point has no parent: {}", target.display()))?;
    let name = target
        .file_name()
        .ok_or_else(|| {
            format!(
                "mount point has no final path component: {}",
                target.display()
            )
        })?
        .to_string_lossy();
    let backup = parent.join(format!(".{name}.macluster-stale-{}", Id128::random()));

    fs::rename(target, &backup).map_err(|error| {
        format!(
            "cannot move stale empty mount point {} aside: {error}",
            target.display()
        )
    })?;
    if let Err(create_error) = fs::create_dir(target) {
        if let Err(restore_error) = fs::rename(&backup, target) {
            return Err(format!(
                "cannot recreate mount point {} ({create_error}); original empty directory remains at {} because restore failed: {restore_error}",
                target.display(),
                backup.display()
            ));
        }
        return Err(format!(
            "cannot recreate mount point {}: {create_error}",
            target.display()
        ));
    }

    let path = std::ffi::CString::new(target.as_os_str().as_bytes())
        .map_err(|error| format!("invalid mount path: {error}"))?;
    if unsafe { libc::chown(path.as_ptr(), metadata.uid(), metadata.gid()) } != 0 {
        let error = std::io::Error::last_os_error();
        let _ = fs::remove_dir(target);
        let _ = fs::rename(&backup, target);
        return Err(format!(
            "cannot preserve ownership for recreated mount point {}: {error}",
            target.display()
        ));
    }
    if let Err(error) =
        fs::set_permissions(target, fs::Permissions::from_mode(metadata.mode() & 0o7777))
    {
        let _ = fs::remove_dir(target);
        let _ = fs::rename(&backup, target);
        return Err(format!(
            "cannot preserve permissions for recreated mount point {}: {error}",
            target.display()
        ));
    }
    fs::remove_dir(&backup).map_err(|error| {
        format!(
            "recreated mount point {} but could not remove its empty stale directory {}: {error}",
            target.display(),
            backup.display()
        )
    })?;
    Ok(())
}
fn force_refresh_mount(
    source: &str,
    target: &Path,
    allow_existing_contents: bool,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<(), String> {
    let mounts = execute("/sbin/mount", &[])?;
    match named_share_mount_status(&mounts, source, &target.to_string_lossy()) {
        NamedShareMountStatus::Expected => {
            execute(
                "/usr/sbin/diskutil",
                &["unmount", "force", &target.to_string_lossy()],
            )?;
            let after_unmount = execute("/sbin/mount", &[])?;
            match named_share_mount_status(&after_unmount, source, &target.to_string_lossy()) {
                NamedShareMountStatus::NotMounted => {}
                NamedShareMountStatus::Expected => {
                    return Err(format!(
                        "unresponsive NFS mount {} remained active after forced unmount",
                        target.display()
                    ));
                }
                NamedShareMountStatus::MountedElsewhere(other) => {
                    return Err(format!(
                        "mount point {} changed to {other} during NFS recovery",
                        target.display()
                    ));
                }
            }
        }
        NamedShareMountStatus::NotMounted => {}
        NamedShareMountStatus::MountedElsewhere(other) => {
            return Err(format!("mount conflict at {}: {other}", target.display()));
        }
    }
    ensure_mount(source, target, allow_existing_contents, execute)
}
fn refresh_if_not_responding(
    source: &str,
    target: &Path,
    allow_existing_contents: bool,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<bool, String> {
    let mounts = execute("/sbin/mount", &[])?;
    if !expected(source, target, &mounts)? {
        return Ok(false);
    }
    // macOS ships nfsstat in /usr/bin (unlike several BSD/Linux layouts).
    let status = execute("/usr/bin/nfsstat", &["-m"])?;
    if !nfs_mount_is_not_responding(&status, target) {
        return Ok(false);
    }
    force_refresh_mount(source, target, allow_existing_contents, execute)?;
    Ok(true)
}
/// Read a share marker as the owning account. These paths can be NFS mounts;
/// never read them directly in the privileged process because a stalled NFS
/// filesystem can block that process in the kernel indefinitely.
pub(crate) fn read_share_marker(target: &Path, uid: u32) -> Result<Option<String>, String> {
    read_share_marker_with(target, |program, args| {
        bounded_as_user_output(program, args, uid)
    })
}

fn read_share_marker_with(
    target: &Path,
    mut execute: impl FnMut(&str, &[&str]) -> Result<std::process::Output, String>,
) -> Result<Option<String>, String> {
    let marker = target.join(".macluster-share-id");
    let marker_text = marker.to_string_lossy();
    let stat = execute("/usr/bin/stat", &["-f", "%HT", &marker_text]).map_err(|error| {
        format!(
            "cannot inspect NFS share marker {}: {error}",
            marker.display()
        )
    })?;
    if !stat.status.success() {
        let stderr = String::from_utf8_lossy(&stat.stderr);
        if stderr.contains("No such file or directory") {
            return Ok(None);
        }
        return Err(format!(
            "cannot inspect NFS share marker {}: {}",
            marker.display(),
            stderr.trim()
        ));
    }
    if String::from_utf8_lossy(&stat.stdout).trim() != "Regular File" {
        return Err(format!(
            "NFS share marker {} is not a regular file",
            marker.display()
        ));
    }
    let output = execute("/bin/cat", &[&marker_text])
        .map_err(|error| format!("cannot read NFS share marker {}: {error}", marker.display()))?;
    if !output.status.success() {
        return Err(format!(
            "cannot read NFS share marker {}: {}",
            marker.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let uuid = raw.trim();
    Id128::parse(uuid)
        .map_err(|error| format!("NFS share marker {} is invalid: {error}", marker.display()))?;
    Ok(Some(uuid.to_owned()))
}

pub(crate) fn remove_share_marker(
    target: &Path,
    expected_uuid: &str,
    uid: u32,
) -> Result<bool, String> {
    let Some(actual) = read_share_marker(target, uid)? else {
        return Ok(false);
    };
    if actual != expected_uuid {
        return Err(format!(
            "share marker {} no longer matches its recorded UUID; refusing removal",
            target.join(".macluster-share-id").display()
        ));
    }
    let marker = target.join(".macluster-share-id");
    let marker_text = marker.to_string_lossy();
    let output = bounded_as_user_output("/bin/rm", &["-f", &marker_text], uid)
        .map_err(|error| format!("cannot remove share marker {}: {error}", marker.display()))?;
    if !output.status.success() {
        return Err(format!(
            "cannot remove share marker {}: {}",
            marker.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(true)
}
fn lock(dir: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("lock"))
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + LOCK_WAIT_TIMEOUT;
    use std::os::fd::AsRawFd;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        if Instant::now() >= deadline {
            return Err("NFS recovery operation is still active; retry shortly".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn plist(target: &Path) -> String {
    let helper = directory(target).join("macluster");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array><string>{}</string><string>internal</string><string>nfs-recovery</string><string>recover</string><string>{}</string></array><key>RunAtLoad</key><true/><key>StartInterval</key><integer>15</integer><key>ProcessType</key><string>Background</string></dict></plist>\n",
        label(target),
        xml(&helper.to_string_lossy()),
        xml(&target.to_string_lossy())
    )
}
fn plist_path(target: &Path) -> PathBuf {
    Path::new("/Library/LaunchDaemons").join(format!("{}.plist", label(target)))
}

fn refreshed_manifest(
    old: Option<Manifest>,
    source: &str,
    target: &Path,
    uuid: &str,
    execution_uid: u32,
    allow_existing_contents: bool,
) -> Result<Manifest, String> {
    let uuid = Id128::parse(uuid).map_err(|e| e.to_string())?.to_string();
    if let Some(old) = old {
        let old_uuid = Id128::parse(&old.uuid)
            .map_err(|e| e.to_string())?
            .to_string();
        if old.target != target || old_uuid != uuid {
            return Err("NFS recovery identity changed; refusing helper refresh".into());
        }
    }
    Ok(Manifest {
        source: source.into(),
        target: target.to_owned(),
        uuid,
        execution_uid,
        allow_existing_contents,
    })
}

fn install_manifest_matches_endpoint(
    old: &Manifest,
    source: &str,
    target: &Path,
) -> Result<(), String> {
    if old.source == source && old.target == target {
        // Enrollment verifies the UUID on the NFS source over SSH. A root
        // LaunchDaemon must not read file data through the NFS mount: macOS
        // TCC can deny background access and trigger repeated remounts.
        Ok(())
    } else {
        Err("another share owns this NFS recovery target; remove it first".into())
    }
}

fn write_launch_daemon(target: &Path) -> Result<(), String> {
    let path = plist_path(target);
    let temp = path.with_extension("next");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    f.write_all(plist(target).as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(temp, &path).map_err(|e| e.to_string())?;
    bounded(
        "/bin/launchctl",
        &["bootstrap", "system", &path.to_string_lossy()],
    )?;
    Ok(())
}
fn write_version(target: &Path) -> Result<(), String> {
    let path = version_marker_path(target);
    let temp = path.with_extension("next");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    file.write_all(helper_version().as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(temp, path).map_err(|error| error.to_string())
}
fn unload(target: &Path) -> Result<(), String> {
    let service = format!("system/{}", label(target));
    match bounded("/bin/launchctl", &["print", &service]) {
        Ok(_) => {
            bounded("/bin/launchctl", &["bootout", &service])?;
        }
        Err(error) if error.contains("Could not find service") => {}
        Err(error) => return Err(error),
    }
    Ok(())
}
fn safe_mount_target(target: &Path, allow_existing_contents: bool) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in target.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err(format!("unsafe mount path {}", current.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    if !allow_existing_contents
        && fs::read_dir(target)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err(format!(
            "mount point {} is not empty; preserving local files",
            target.display()
        ));
    }
    Ok(())
}
fn recover_mount(
    manifest: &Manifest,
    mut execute: impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<(), String> {
    let target = &manifest.target;
    ensure_mount(
        &manifest.source,
        target,
        manifest.allow_existing_contents,
        &mut execute,
    )?;
    refresh_if_not_responding(
        &manifest.source,
        target,
        manifest.allow_existing_contents,
        &mut execute,
    )?;
    Ok(())
}

fn next_delay(failures: u32) -> u64 {
    15u64.saturating_mul(1u64 << failures.saturating_sub(1).min(2))
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("NFS recovery setup requires administrator authorization".into());
    }
    let action = args.first().map(String::as_str).unwrap_or("");
    let target = match (action, args.len()) {
        ("recover", 2) => Path::new(&args[1]),
        ("install", 5 | 6) | ("remove", 4) => Path::new(&args[2]),
        ("refresh", 5 | 6) => Path::new(&args[2]),
        _ => return Err("invalid internal NFS recovery arguments".into()),
    };
    valid_target(target)?;
    secure_dir(Path::new(ROOT))?;
    let dir = directory(target);
    secure_dir(&dir)?;
    let _guard = lock(&dir)?;
    let manifest_path = dir.join("manifest.json");
    match action {
        "install" => {
            let allow_existing_contents = match args.get(5).map(String::as_str) {
                None => false,
                Some("--overlay-existing") => true,
                Some(_) => return Err("invalid NFS recovery overlay option".into()),
            };
            let source = &args[1];
            let uuid = Id128::parse(&args[3])
                .map_err(|error| format!("invalid NFS recovery share UUID: {error}"))?
                .to_string();
            if !expected(source, target, &mount_table()?)? {
                return Err("cannot authorize recovery before the NFS mount is verified".into());
            }
            let execution_uid = args[4]
                .parse::<u32>()
                .map_err(|_| "invalid NFS recovery execution UID".to_owned())?;
            refresh_if_not_responding(
                source,
                target,
                allow_existing_contents,
                &mut |program, args| bounded(program, args),
            )?;
            if manifest_path.exists() {
                let old: Manifest =
                    serde_json::from_slice(&fs::read(&manifest_path).map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                install_manifest_matches_endpoint(&old, source, target)?;
            }
            unload(target)?;
            write_json(
                &manifest_path,
                &Manifest {
                    source: source.clone(),
                    target: target.to_owned(),
                    uuid,
                    execution_uid,
                    allow_existing_contents,
                },
            )?;
            write_json(&dir.join("status.json"), &Status::default())?;
            write_launch_daemon(target)?;
            write_version(target)
        }
        "refresh" => {
            let allow_existing_contents = match args.get(5).map(String::as_str) {
                None => false,
                Some("--overlay-existing") => true,
                Some(_) => return Err("invalid NFS recovery overlay option".into()),
            };
            let source = &args[1];
            let uuid = Id128::parse(&args[3])
                .map_err(|e| e.to_string())?
                .to_string();
            let execution_uid = args[4]
                .parse::<u32>()
                .map_err(|_| "invalid NFS recovery execution UID".to_owned())?;
            let old = match fs::read(&manifest_path) {
                Ok(raw) => Some(serde_json::from_slice(&raw).map_err(|e| e.to_string())?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.to_string()),
            };
            let manifest = refreshed_manifest(
                old,
                source,
                target,
                &uuid,
                execution_uid,
                allow_existing_contents,
            )?;
            unload(target)?;
            write_json(&manifest_path, &manifest)?;
            if !dir.join("status.json").exists() {
                write_json(&dir.join("status.json"), &Status::default())?;
            }
            write_launch_daemon(target)?;
            write_version(target)
        }
        "remove" => {
            if manifest_path.exists() {
                let manifest: Manifest =
                    serde_json::from_slice(&fs::read(&manifest_path).map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                if manifest.source != args[1]
                    || manifest.uuid != args[3]
                    || manifest.target != target
                {
                    return Err("NFS recovery identity changed; refusing cleanup".into());
                }
            }
            unload(target)?;
            for p in [
                plist_path(target),
                manifest_path,
                dir.join("status.json"),
                dir.join("version"),
                dir.join("version.next"),
                dir.join("macluster"),
            ] {
                match fs::remove_file(p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            Ok(())
        }
        "recover" => {
            // A removed manifest fences queued/late invocations after reset.
            let manifest: Manifest = match fs::read(&manifest_path) {
                Ok(raw) => serde_json::from_slice(&raw).map_err(|e| e.to_string())?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.to_string()),
            };
            if manifest.target != target {
                return Err("NFS recovery target mismatch".into());
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut status: Status = fs::read(dir.join("status.json"))
                .ok()
                .and_then(|s| serde_json::from_slice(&s).ok())
                .unwrap_or_default();
            if now < status.retry_after {
                return Ok(());
            }
            let result = recover_mount(&manifest, |program, args| {
                if matches!(program, "/bin/cat" | "/usr/bin/stat") {
                    bounded_as_user(program, args, manifest.execution_uid)
                } else {
                    bounded(program, args)
                }
            });
            match &result {
                Ok(()) => {
                    if status.failures == 0 {
                        return Ok(());
                    }
                    status = Status::default()
                }
                Err(e) => {
                    status.failures = status.failures.saturating_add(1);
                    status.retry_after = now + next_delay(status.failures);
                    status.error = Some(e.clone())
                }
            }
            write_json(&dir.join("status.json"), &status)?;
            result
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stalled_network_marker_read_returns_a_path_specific_timeout() {
        use std::os::unix::process::ExitStatusExt;

        let target = Path::new("/Users/operator/.cargo");
        let error = read_share_marker_with(target, |program, _args| {
            if program == "/usr/bin/stat" {
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: b"Regular File\n".to_vec(),
                    stderr: Vec::new(),
                })
            } else {
                Err("node transport timed out".into())
            }
        })
        .expect_err("a blocked NFS marker read must fail within its command timeout");

        assert!(error.contains("/Users/operator/.cargo/.macluster-share-id"));
        assert!(error.contains("node transport timed out"));
    }

    #[test]
    fn retry_can_refresh_recovery_uuid_only_for_the_same_nfs_endpoint() {
        let old = Manifest {
            source: "192.0.2.1:/Users/operator/.cargo".into(),
            target: PathBuf::from("/Users/operator/.cargo"),
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            execution_uid: 501,
            allow_existing_contents: true,
        };
        assert!(
            install_manifest_matches_endpoint(
                &old,
                "192.0.2.1:/Users/operator/.cargo",
                Path::new("/Users/operator/.cargo")
            )
            .is_ok()
        );
        assert!(
            install_manifest_matches_endpoint(
                &old,
                "192.0.2.2:/Users/operator/.cargo",
                Path::new("/Users/operator/.cargo")
            )
            .is_err()
        );
        assert!(
            install_manifest_matches_endpoint(
                &old,
                "192.0.2.1:/Users/operator/.cargo",
                Path::new("/Users/other/.cargo")
            )
            .is_err()
        );
    }

    #[test]
    fn share_marker_reader_checks_the_file_as_the_configured_user() {
        let uid = unsafe { libc::geteuid() as u32 };
        if uid == 0 {
            return;
        }
        let target = std::env::temp_dir().join(format!("nfs-marker-reader-{}", Id128::random()));
        fs::create_dir_all(&target).unwrap();
        let uuid = "00000000-0000-4000-8000-000000000001";
        fs::write(target.join(".macluster-share-id"), format!("{uuid}\n")).unwrap();

        assert_eq!(
            read_share_marker(&target, uid).unwrap().as_deref(),
            Some(uuid)
        );
        fs::remove_file(target.join(".macluster-share-id")).unwrap();
        assert_eq!(read_share_marker(&target, uid).unwrap(), None);
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn current_version_does_not_mask_missing_installation_files_or_service() {
        let dir = std::env::temp_dir().join(format!("nfs-install-check-{}", Id128::random()));
        fs::create_dir_all(&dir).unwrap();
        let plist = dir.join("service.plist");
        let launchctl = dir.join("launchctl");
        use std::os::unix::fs::PermissionsExt;
        fs::write(&launchctl, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&launchctl, fs::Permissions::from_mode(0o755)).unwrap();
        let files = [
            dir.join("macluster"),
            dir.join("manifest.json"),
            plist.clone(),
        ];
        for file in &files {
            fs::write(file, "installed").unwrap();
        }
        fs::write(dir.join("version"), helper_version()).unwrap();
        let script = installation_check_script(&dir, &plist, "test.service", &launchctl);
        let check = || {
            Command::new("/bin/sh")
                .args(["-c", &script])
                .status()
                .unwrap()
                .success()
        };
        assert!(check());
        for file in &files {
            fs::remove_file(file).unwrap();
            assert!(!check(), "missing {} must require repair", file.display());
            fs::write(file, "installed").unwrap();
        }
        fs::write(&launchctl, "#!/bin/sh\nexit 1\n").unwrap();
        assert!(!check(), "an unloaded service must require repair");
        fs::write(&launchctl, "#!/bin/sh\nexit 0\n").unwrap();
        fs::write(dir.join("version"), "old-service-version").unwrap();
        assert!(!check());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn helper_version_is_independent_of_agent_build_and_source_text() {
        let target = Path::new("/Users/Shared/tools");
        let marker = version_marker_path(target);
        assert_eq!(marker, directory(target).join("version"));
        let version = helper_version();
        assert_eq!(version, SERVICE_VERSION);
        assert_eq!(version, "nfs-recovery-7");
    }

    #[test]
    fn refresh_script_verifies_staged_binary_before_replacing_root_helper() {
        let script = refresh_script(
            "/Users/worker/.local/bin/macluster",
            &"a".repeat(64),
            "192.0.2.1:/tools",
            Path::new("/Users/Shared/tools"),
            "00000000-0000-4000-8000-000000000001",
            Some(501),
            true,
        );
        assert!(script.contains("checksum mismatch"));
        assert!(script.contains("internal nfs-recovery refresh"));
        assert!(script.contains("00000000-0000-4000-8000-000000000001"));
        assert!(script.contains("macluster.next"));
        let syntax = std::process::Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "{}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[test]
    fn install_script_passes_the_source_validated_uuid_to_recovery() {
        let script = install_script(
            "/Users/operator/.local/bin/macluster",
            "192.0.2.1:/tools",
            Path::new("/Users/Shared/tools"),
            "00000000-0000-4000-8000-000000000001",
            Some(501),
            false,
        );

        assert!(script.contains(
            "internal nfs-recovery install '192.0.2.1:/tools' '/Users/Shared/tools' '00000000-0000-4000-8000-000000000001' 501"
        ));
        assert!(!script.contains("/bin/cat"));
        let syntax = Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "{}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[test]
    fn refresh_tracks_source_migration_but_refuses_share_identity_changes() {
        let target = Path::new("/Users/Shared/tools");
        let old = Manifest {
            source: "192.0.2.1:/tools".into(),
            target: target.into(),
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            execution_uid: 501,
            allow_existing_contents: false,
        };
        let refreshed = refreshed_manifest(
            Some(old.clone()),
            "192.0.2.3:/tools",
            target,
            "00000000-0000-4000-8000-000000000001",
            501,
            false,
        )
        .unwrap();
        assert_eq!(refreshed.source, "192.0.2.3:/tools");
        assert!(
            refreshed_manifest(
                Some(old),
                "192.0.2.1:/tools",
                target,
                "00000000-0000-4000-8000-000000000002",
                501,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn removal_lock_wait_covers_one_full_recovery_attempt() {
        const MAX_RECOVERY_CHILD_COMMANDS: u32 = 5;
        assert!(
            LOCK_WAIT_TIMEOUT >= COMMAND_TIMEOUT * MAX_RECOVERY_CHILD_COMMANDS,
            "removal can time out while a bounded recovery attempt still holds the lock"
        );
    }

    #[test]
    fn rejects_foreign_and_stacked_mounts() {
        let target = Path::new("/Volumes/test");
        assert_eq!(
            expected(
                "192.0.2.1:/data",
                target,
                "192.0.2.1:/data on /Volumes/test (nfs, nodev)\n"
            )
            .unwrap(),
            true
        );
        assert!(!expected("192.0.2.1:/data", target, "").unwrap());
        assert!(
            expected(
                "192.0.2.1:/data",
                target,
                "192.0.2.2:/other on /Volumes/test (nfs)\n"
            )
            .is_err()
        );
        assert!(
            expected(
                "192.0.2.1:/data",
                target,
                "192.0.2.1:/data on /Volumes/test (nfs)\n192.0.2.1:/data on /Volumes/test (nfs)\n"
            )
            .is_err()
        );
    }
    #[test]
    fn launchd_arguments_are_escaped_and_target_scoped() {
        let a = Path::new("/Volumes/a & b");
        let b = Path::new("/Volumes/b");
        assert_ne!(label(a), label(b));
        assert!(plist(a).contains("a &amp; b"));
        assert!(plist(a).contains("<key>RunAtLoad</key><true/>"));
        assert!(plist(a).contains("<key>StartInterval</key>"));
    }
    #[test]
    fn recovery_never_covers_local_data_or_symlinks() {
        let dir = std::env::temp_dir().join(format!("nfs-recovery-{}", Id128::random()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("keep"), b"data").unwrap();
        assert!(safe_mount_target(&dir, false).is_err());
        assert_eq!(fs::read(dir.join("keep")).unwrap(), b"data");
        let link = dir.with_extension("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(safe_mount_target(&link, true).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicitly_authorized_overlay_recovery_preserves_local_files() {
        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-overlay-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        fs::write(target.join("local-brew"), b"keep").unwrap();
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "source": "192.0.2.1:/opt/homebrew",
            "target": target,
            "uuid": "00000000-0000-4000-8000-000000000001",
            "execution_uid": 501,
            "allow_existing_contents": true
        }))
        .unwrap();
        let mut mounted = false;
        let result = recover_mount(&manifest, |program, _args| match program {
            "/sbin/mount" => Ok(if mounted {
                format!(
                    "{} on {} (nfs)\n",
                    manifest.source,
                    manifest.target.display()
                )
            } else {
                String::new()
            }),
            "/sbin/mount_nfs" => {
                mounted = true;
                Ok(String::new())
            }
            "/usr/bin/nfsstat" => Ok(format!(
                "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x0\n",
                manifest.target.display(),
                manifest.source
            )),
            "/usr/bin/stat" => Ok("Regular File".into()),
            "/bin/cat" => Ok(manifest.uuid.clone()),
            _ => panic!("unexpected command {program}"),
        });

        assert!(result.is_ok(), "overlay recovery failed: {result:?}");
        assert_eq!(fs::read(target.join("local-brew")).unwrap(), b"keep");
        fs::remove_file(target.join("local-brew")).unwrap();
        fs::remove_dir(target).unwrap();
    }
    #[test]
    fn retry_after_network_failure_restores_once_and_checks_mount_health() {
        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-retry-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        let manifest = Manifest {
            source: "192.0.2.1:/data".into(),
            target: target.clone(),
            uuid: Id128::random().to_string(),
            execution_uid: 501,
            allow_existing_contents: false,
        };
        let mut mounted = false;
        let mut network_ready = false;
        let mut attempts = 0;
        let mut command = |program: &str, _args: &[&str]| -> Result<String, String> {
            match program {
                "/sbin/mount" => Ok(if mounted {
                    format!("{} on {} (nfs)\n", manifest.source, target.display())
                } else {
                    String::new()
                }),
                "/sbin/mount_nfs" => {
                    attempts += 1;
                    if !network_ready {
                        return Err("network unavailable".into());
                    }
                    mounted = true;
                    Ok(String::new())
                }
                "/usr/bin/nfsstat" => Ok(format!(
                    "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x0\n",
                    target.display(),
                    manifest.source
                )),
                "/usr/bin/stat" => Ok("Regular File".into()),
                "/bin/cat" => Ok(manifest.uuid.clone()),
                _ => panic!("unexpected command"),
            }
        };
        assert!(recover_mount(&manifest, &mut command).is_err());
        drop(command);
        network_ready = true;
        let mut command = |program: &str, _args: &[&str]| -> Result<String, String> {
            match program {
                "/sbin/mount" => Ok(if mounted {
                    format!("{} on {} (nfs)\n", manifest.source, target.display())
                } else {
                    String::new()
                }),
                "/sbin/mount_nfs" => {
                    attempts += 1;
                    assert!(network_ready);
                    mounted = true;
                    Ok(String::new())
                }
                "/usr/bin/nfsstat" => Ok(format!(
                    "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x0\n",
                    target.display(),
                    manifest.source
                )),
                "/usr/bin/stat" => Ok("Regular File".into()),
                "/bin/cat" => Ok(manifest.uuid.clone()),
                _ => panic!("unexpected command"),
            }
        };
        recover_mount(&manifest, &mut command).unwrap();
        recover_mount(&manifest, &mut command).unwrap();
        drop(command);
        assert_eq!(attempts, 2);
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn busy_empty_mountpoint_is_recreated_and_mount_is_retried_once() {
        use std::os::unix::fs::MetadataExt;

        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-busy-mountpoint-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        let original_metadata = fs::metadata(&target).unwrap();
        let manifest = Manifest {
            source: "192.0.2.1:/data".into(),
            target: target.clone(),
            uuid: Id128::random().to_string(),
            execution_uid: unsafe { libc::geteuid() as u32 },
            allow_existing_contents: false,
        };
        let mut mounted = false;
        let mut mount_attempts = 0;
        let result = recover_mount(&manifest, |program, _args| match program {
            "/sbin/mount" => Ok(if mounted {
                format!("{} on {} (nfs)\n", manifest.source, target.display())
            } else {
                String::new()
            }),
            "/sbin/mount_nfs" => {
                mount_attempts += 1;
                if mount_attempts == 1 {
                    Err("mount_nfs: Resource busy".into())
                } else {
                    mounted = true;
                    Ok(String::new())
                }
            }
            "/usr/sbin/lsof" => Ok(String::new()),
            "/usr/bin/nfsstat" => Ok(format!(
                "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x0\n",
                target.display(),
                manifest.source
            )),
            _ => panic!("unexpected command {program}"),
        });

        assert!(
            result.is_ok(),
            "busy mountpoint recovery failed: {result:?}"
        );
        assert_eq!(mount_attempts, 2, "recovery must retry exactly once");
        let recreated_metadata = fs::metadata(&target).unwrap();
        assert_ne!(
            recreated_metadata.ino(),
            original_metadata.ino(),
            "the stale empty mountpoint directory must be replaced"
        );
        assert_eq!(recreated_metadata.uid(), original_metadata.uid());
        assert_eq!(recreated_metadata.gid(), original_metadata.gid());
        assert_eq!(
            recreated_metadata.mode() & 0o7777,
            original_metadata.mode() & 0o7777
        );
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn busy_mountpoint_with_local_files_is_preserved_without_retry() {
        use std::os::unix::fs::MetadataExt;

        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-busy-data-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        let local_file = target.join("keep.txt");
        fs::write(&local_file, b"user data").unwrap();
        let original_inode = fs::metadata(&target).unwrap().ino();
        let manifest = Manifest {
            source: "192.0.2.1:/data".into(),
            target: target.clone(),
            uuid: Id128::random().to_string(),
            execution_uid: unsafe { libc::geteuid() as u32 },
            allow_existing_contents: true,
        };
        let mut mount_attempts = 0;
        let error =
            ensure_mount(
                &manifest.source,
                &target,
                true,
                &mut |program, _args| match program {
                    "/sbin/mount" => Ok(String::new()),
                    "/sbin/mount_nfs" => {
                        mount_attempts += 1;
                        Err("mount_nfs: Resource busy".into())
                    }
                    "/usr/sbin/lsof" => Ok(String::new()),
                    _ => panic!("unexpected command {program}"),
                },
            )
            .expect_err("recovery must not replace a mountpoint containing local files");

        assert!(error.contains("contains local files"), "{error}");
        assert_eq!(mount_attempts, 1);
        assert_eq!(fs::read(&local_file).unwrap(), b"user data");
        assert_eq!(fs::metadata(&target).unwrap().ino(), original_inode);
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn busy_mountpoint_used_by_a_process_is_not_recreated() {
        use std::os::unix::fs::MetadataExt;

        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-busy-process-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        let original_inode = fs::metadata(&target).unwrap().ino();
        let source = "192.0.2.1:/data";
        let mut mount_attempts = 0;
        let error = ensure_mount(
            source,
            &target,
            false,
            &mut |program, _args| match program {
                "/sbin/mount" => Ok(String::new()),
                "/sbin/mount_nfs" => {
                    mount_attempts += 1;
                    Err("mount_nfs: Resource busy".into())
                }
                "/usr/sbin/lsof" => Ok("worker 123 user cwd DIR 1,1 64 2 /target\n".into()),
                _ => panic!("unexpected command {program}"),
            },
        )
        .expect_err("recovery must not replace a mountpoint held open by a process");

        assert!(error.contains("in use"), "{error}");
        assert_eq!(mount_attempts, 1);
        assert_eq!(fs::metadata(&target).unwrap().ino(), original_inode);
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn busy_mountpoint_that_becomes_a_foreign_mount_is_preserved() {
        use std::os::unix::fs::MetadataExt;

        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-busy-foreign-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        let original_inode = fs::metadata(&target).unwrap().ino();
        let source = "192.0.2.1:/expected";
        let mut mount_checks = 0;
        let mut mount_attempts = 0;
        let mut lsof_called = false;
        let error = ensure_mount(
            source,
            &target,
            false,
            &mut |program, _args| match program {
                "/sbin/mount" => {
                    mount_checks += 1;
                    Ok(if mount_checks == 1 {
                        String::new()
                    } else {
                        format!("192.0.2.9:/foreign on {} (nfs)\n", target.display())
                    })
                }
                "/sbin/mount_nfs" => {
                    mount_attempts += 1;
                    Err("mount_nfs: Resource busy".into())
                }
                "/usr/sbin/lsof" => {
                    lsof_called = true;
                    Ok(String::new())
                }
                _ => panic!("unexpected command {program}"),
            },
        )
        .expect_err("a foreign mount must be treated as a conflict");

        assert!(error.contains("mount conflict"), "{error}");
        assert_eq!(mount_attempts, 1);
        assert!(!lsof_called);
        assert_eq!(fs::metadata(&target).unwrap().ino(), original_inode);
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn nfsstat_unresponsive_status_matches_the_requested_mount_only() {
        let output = concat!(
            "/Users/Shared/macluster from 192.0.2.1:/Users/Shared/macluster\n",
            "  -- Current mount parameters:\n",
            "     Status flags: 0x2,not responding\n\n",
            "/Users/operator/mamba from 192.0.2.1:/Users/operator/mamba\n",
            "  -- Current mount parameters:\n",
            "     Status flags: 0x0\n"
        );

        assert!(nfs_mount_is_not_responding(
            output,
            Path::new("/Users/Shared/macluster")
        ));
        assert!(!nfs_mount_is_not_responding(
            output,
            Path::new("/Users/operator/mamba")
        ));
        assert!(!nfs_mount_is_not_responding(
            output,
            Path::new("/Users/Shared")
        ));
    }

    #[test]
    fn recovery_forces_an_exact_unresponsive_mount_to_remount() {
        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-unresponsive-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        fs::write(target.join("local-data"), b"preserve me").unwrap();
        let manifest = Manifest {
            source: "192.0.2.1:/opt/homebrew".into(),
            target: target.clone(),
            uuid: Id128::random().to_string(),
            execution_uid: 501,
            allow_existing_contents: true,
        };
        let mut mounted = true;
        let mut unmounts = 0;
        let mut mount_attempts = 0;
        let result = recover_mount(&manifest, |program, args| match program {
            "/sbin/mount" => Ok(if mounted {
                format!(
                    "{} on {} (nfs)\n",
                    manifest.source,
                    manifest.target.display()
                )
            } else {
                String::new()
            }),
            "/usr/bin/nfsstat" => Ok(if mounted && unmounts == 0 {
                format!(
                    "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x2,not responding\n",
                    manifest.target.display(),
                    manifest.source
                )
            } else {
                format!(
                    "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x0\n",
                    manifest.target.display(),
                    manifest.source
                )
            }),
            "/usr/sbin/diskutil" => {
                assert_eq!(args.first(), Some(&"unmount"));
                assert_eq!(args.get(1), Some(&"force"));
                assert_eq!(
                    args.get(2),
                    Some(&manifest.target.to_string_lossy().as_ref())
                );
                unmounts += 1;
                mounted = false;
                Ok(String::new())
            }
            "/sbin/mount_nfs" => {
                mount_attempts += 1;
                mounted = true;
                Ok(String::new())
            }
            "/usr/bin/stat" => Ok("Regular File".into()),
            "/bin/cat" => Ok(manifest.uuid.clone()),
            _ => panic!("unexpected command {program}"),
        });

        assert!(result.is_ok(), "recovery failed: {result:?}");
        assert_eq!(unmounts, 1);
        assert_eq!(mount_attempts, 1);
        assert_eq!(fs::read(target.join("local-data")).unwrap(), b"preserve me");
        fs::remove_file(target.join("local-data")).unwrap();
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn healthy_recovery_does_not_read_markers_or_recycle_the_mount() {
        let target = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nfs-marker-retry-{}", Id128::random()));
        fs::create_dir(&target).unwrap();
        let manifest = Manifest {
            source: "192.0.2.1:/opt/homebrew".into(),
            target: target.clone(),
            uuid: Id128::random().to_string(),
            execution_uid: 501,
            allow_existing_contents: true,
        };
        let mut mounted = true;
        let mut unmounts = 0;
        let mut mount_attempts = 0;
        let mut marker_reads = 0;
        let result = recover_mount(&manifest, |program, _args| match program {
            "/sbin/mount" => Ok(if mounted {
                format!(
                    "{} on {} (nfs)\n",
                    manifest.source,
                    manifest.target.display()
                )
            } else {
                String::new()
            }),
            "/usr/bin/nfsstat" => Ok(format!(
                "{} from {}\n  -- Current mount parameters:\n     Status flags: 0x0\n",
                manifest.target.display(),
                manifest.source
            )),
            "/usr/sbin/diskutil" => {
                unmounts += 1;
                mounted = false;
                Ok(String::new())
            }
            "/sbin/mount_nfs" => {
                mount_attempts += 1;
                mounted = true;
                Ok(String::new())
            }
            "/usr/bin/stat" => Ok("Regular File".into()),
            "/bin/cat" => {
                marker_reads += 1;
                if marker_reads == 1 {
                    Err("Interrupted system call".into())
                } else {
                    Ok(manifest.uuid.clone())
                }
            }
            _ => panic!("unexpected command {program}"),
        });

        assert!(result.is_ok(), "recovery failed: {result:?}");
        assert_eq!(unmounts, 0, "a healthy mount must not be force-unmounted");
        assert_eq!(mount_attempts, 0, "a healthy mount must not be remounted");
        assert_eq!(marker_reads, 0, "LaunchDaemons must not read NFS files");
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn recovery_refuses_to_mount_over_an_unrelated_filesystem() {
        let manifest = Manifest {
            source: "192.0.2.1:/data".into(),
            target: PathBuf::from("/Volumes/example"),
            uuid: Id128::random().to_string(),
            execution_uid: 501,
            allow_existing_contents: false,
        };
        let mut calls = 0;
        let result = recover_mount(&manifest, |program, _| {
            calls += 1;
            assert_eq!(program, "/sbin/mount");
            Ok("/dev/disk9 on /Volumes/example (apfs, local)\n".into())
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(
            [
                next_delay(1),
                next_delay(2),
                next_delay(3),
                next_delay(u32::MAX)
            ],
            [15, 30, 60, 60]
        );
    }
}
