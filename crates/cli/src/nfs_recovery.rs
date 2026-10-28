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
    execution_uid: Option<u32>,
) -> String {
    let dir = quote(&directory(target).to_string_lossy());
    let uid = execution_uid
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| "${SUDO_UID:?missing execution UID}".into());
    format!(
        "[ ! -L {root} ] && [ ! -L {dir} ] || {{ echo 'unsafe NFS recovery install path' >&2; exit 1; }}\n/bin/mkdir -p {dir}\n/usr/sbin/chown root:wheel {root}\n/bin/chmod 755 {root}\n/usr/sbin/chown root:wheel {dir}\n/bin/chmod 755 {dir}\n/usr/bin/install -o root -g wheel -m 700 {} {dir}/macluster.next\n/bin/mv -f {dir}/macluster.next {dir}/macluster\n{dir}/macluster internal nfs-recovery install {} {} {uid}\n",
        quote(binary),
        quote(source),
        quote(&target.to_string_lossy()),
        root = quote(ROOT),
    )
}

pub(crate) fn refresh_script(
    binary: &str,
    source: &str,
    target: &Path,
    uuid: &str,
    execution_uid: Option<u32>,
) -> String {
    let dir = quote(&directory(target).to_string_lossy());
    let uid = execution_uid
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| "${SUDO_UID:?missing execution UID}".into());
    format!(
        "[ ! -L {root} ] && [ ! -L {dir} ] || {{ echo 'unsafe NFS recovery install path' >&2; exit 1; }}\n/bin/mkdir -p {dir}\n/usr/sbin/chown root:wheel {root}\n/bin/chmod 755 {root}\n/usr/sbin/chown root:wheel {dir}\n/bin/chmod 755 {dir}\n/usr/bin/install -o root -g wheel -m 700 {} {dir}/macluster.next\n/bin/mv -f {dir}/macluster.next {dir}/macluster\n{dir}/macluster internal nfs-recovery refresh {} {} {} {uid}\n",
        quote(binary),
        quote(source),
        quote(&target.to_string_lossy()),
        quote(uuid),
        root = quote(ROOT),
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
    bounded_command(command)
}
fn bounded_command(command: Command) -> Result<String, String> {
    let out = macluster_controller::transport::run_child_bounded(command, None, COMMAND_TIMEOUT)
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
fn marker(target: &Path, uid: u32) -> Result<String, String> {
    let marker = target.join(".macluster-share-id");
    if bounded_as_user(
        "/usr/bin/stat",
        &["-f", "%HT", &marker.to_string_lossy()],
        uid,
    )?
    .trim()
        != "Regular File"
    {
        return Err("NFS share marker must be a regular file".into());
    }
    let raw = bounded_as_user("/bin/cat", &[&marker.to_string_lossy()], uid)?;
    Id128::parse(raw.trim()).map_err(|e| e.to_string())?;
    Ok(raw.trim().to_owned())
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
    })
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
fn safe_empty_target(target: &Path) -> Result<(), String> {
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
    if fs::read_dir(target)
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
    if !expected(&manifest.source, target, &execute("/sbin/mount", &[])?)? {
        safe_empty_target(target)?;
        execute(
            "/sbin/mount_nfs",
            &[
                "-o",
                "resvport",
                &manifest.source,
                &target.to_string_lossy(),
            ],
        )?;
        if !expected(&manifest.source, target, &execute("/sbin/mount", &[])?)? {
            return Err("NFS mount did not appear after recovery".into());
        }
    }
    let marker = target.join(".macluster-share-id");
    if execute("/usr/bin/stat", &["-f", "%HT", &marker.to_string_lossy()])?.trim() != "Regular File"
    {
        return Err("NFS share marker must be a regular file".into());
    }
    let actual = execute("/bin/cat", &[&marker.to_string_lossy()])?;
    if actual.trim() != manifest.uuid {
        return Err("restored NFS share identity does not match authorization".into());
    }
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
        ("install", 4) | ("remove", 4) => Path::new(&args[2]),
        ("refresh", 5) => Path::new(&args[2]),
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
            let source = &args[1];
            if !expected(source, target, &mount_table()?)? {
                return Err("cannot authorize recovery before the NFS mount is verified".into());
            }
            let execution_uid = args[3]
                .parse::<u32>()
                .map_err(|_| "invalid NFS recovery execution UID".to_owned())?;
            let uuid = marker(target, execution_uid)?;
            if manifest_path.exists() {
                let old: Manifest =
                    serde_json::from_slice(&fs::read(&manifest_path).map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                if old.uuid != uuid || old.target != target {
                    return Err(
                        "another share owns this NFS recovery target; remove it first".into(),
                    );
                }
            }
            unload(target)?;
            write_json(
                &manifest_path,
                &Manifest {
                    source: source.clone(),
                    target: target.to_owned(),
                    uuid,
                    execution_uid,
                },
            )?;
            write_json(&dir.join("status.json"), &Status::default())?;
            write_launch_daemon(target)
        }
        "refresh" => {
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
            let manifest = refreshed_manifest(old, source, target, &uuid, execution_uid)?;
            unload(target)?;
            write_json(&manifest_path, &manifest)?;
            if !dir.join("status.json").exists() {
                write_json(&dir.join("status.json"), &Status::default())?;
            }
            write_launch_daemon(target)
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
    fn refresh_can_reinstall_helper_while_nfs_is_unmounted() {
        let target = Path::new("/Users/Shared/tools");
        let uuid = "00000000-0000-4000-8000-000000000001";
        let manifest = refreshed_manifest(None, "192.0.2.1:/tools", target, uuid, 501).unwrap();
        assert_eq!(manifest.source, "192.0.2.1:/tools");
        assert_eq!(manifest.target, target);
        assert_eq!(manifest.uuid, uuid);
        assert_eq!(manifest.execution_uid, 501);

        let script = refresh_script(
            "/Users/worker/.local/bin/macluster",
            &manifest.source,
            target,
            uuid,
            Some(501),
        );
        assert!(script.contains("internal nfs-recovery refresh"));
        assert!(script.contains(uuid));
        assert!(!script.contains("internal nfs-recovery install"));
    }

    #[test]
    fn refresh_tracks_source_migration_but_refuses_share_identity_changes() {
        let target = Path::new("/Users/Shared/tools");
        let old = Manifest {
            source: "192.0.2.1:/tools".into(),
            target: target.into(),
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            execution_uid: 501,
        };
        let refreshed = refreshed_manifest(
            Some(old.clone()),
            "192.0.2.3:/tools",
            target,
            "00000000-0000-4000-8000-000000000001",
            501,
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
        assert!(safe_empty_target(&dir).is_err());
        assert_eq!(fs::read(dir.join("keep")).unwrap(), b"data");
        let link = dir.with_extension("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(safe_empty_target(&link).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn retry_after_network_failure_restores_once_and_then_only_checks_mount_table() {
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
    fn recovery_refuses_to_mount_over_an_unrelated_filesystem() {
        let manifest = Manifest {
            source: "192.0.2.1:/data".into(),
            target: PathBuf::from("/Volumes/example"),
            uuid: Id128::random().to_string(),
            execution_uid: 501,
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
