use macluster_protocol::control::ClientDescriptor;
use std::{
    collections::BTreeSet,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::Command,
};

use crate::nfs_recovery::{NFS_MOUNT_LOCK_PATH, NFS_MOUNT_OPTIONS, NFS_MOUNT_TIMEOUT_SECS};
use crate::node_admin::shell_quote;

const HELPER_ROOT: &str = "/Library/PrivilegedHelperTools";
const DAEMON_ROOT: &str = "/Library/LaunchDaemons";
const SMB_BACKING_ROOT: &str = "/Users/Shared/.macluster-mounts";

fn is_managed_smb_backing_alias(path: &Path) -> bool {
    path.starts_with(SMB_BACKING_ROOT) && path != Path::new(SMB_BACKING_ROOT)
}

fn source_is_client_local(source_host: &str, client_ip: &str) -> bool {
    source_host == client_ip
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ClientMount {
    protocol: String,
    source: String,
    physical_target: String,
    logical_target: String,
    alias_suffix: Option<String>,
    share_uuid: String,
}

impl ClientMount {
    fn is_nfs(&self) -> bool {
        self.protocol == "nfs"
    }

    fn is_smb(&self) -> bool {
        self.protocol == "smb"
    }

    fn backing_alias(&self) -> String {
        match self.alias_suffix.as_deref() {
            Some(suffix) if !suffix.is_empty() => {
                format!("{}/{}", self.physical_target.trim_end_matches('/'), suffix)
            }
            _ => self.physical_target.clone(),
        }
    }
}

fn smb_mount(share: &macluster_protocol::control::ClientShareDescriptor) -> ClientMount {
    let path = share.source_root.trim_start_matches('/');
    let (share_name, subpath) = path.split_once('/').unwrap_or((path, ""));
    let authority = share
        .smb_user
        .as_deref()
        .map(|user| format!("{user}@{}", share.server_host))
        .unwrap_or_else(|| share.server_host.clone());
    ClientMount {
        protocol: "smb".into(),
        source: format!("//{authority}/{share_name}"),
        physical_target: format!(
            "/Users/Shared/.macluster-mounts/{}",
            share.share_uuid.trim()
        ),
        logical_target: share.mount_root.clone(),
        alias_suffix: (!subpath.is_empty()).then(|| subpath.to_owned()),
        share_uuid: share.share_uuid.clone(),
    }
}

fn mounts(descriptor: &ClientDescriptor, client_ip: &str) -> Vec<ClientMount> {
    let mut mounts = Vec::new();
    if !source_is_client_local(&descriptor.primary_source_host, client_ip) {
        mounts.push(ClientMount {
            protocol: "nfs".into(),
            source: format!(
                "{}:{}",
                descriptor.primary_source_host, descriptor.primary_source_root
            ),
            physical_target: descriptor.primary_mount_root.clone(),
            logical_target: descriptor.primary_mount_root.clone(),
            alias_suffix: None,
            share_uuid: descriptor.cluster_uuid.clone(),
        });
    }
    mounts.extend(
        descriptor
            .shares
            .iter()
            .filter(|share| !source_is_client_local(&share.server_host, client_ip))
            .map(|share| {
                if share.protocol == "smb" {
                    smb_mount(share)
                } else {
                    ClientMount {
                        protocol: "nfs".into(),
                        source: format!("{}:{}", share.server_host, share.source_root),
                        physical_target: share.mount_root.clone(),
                        logical_target: share.mount_root.clone(),
                        alias_suffix: None,
                        share_uuid: share.share_uuid.clone(),
                    }
                }
            }),
    );
    mounts
}

pub(crate) fn mount_layout_matches(
    left: &ClientDescriptor,
    right: &ClientDescriptor,
    client_ip: &str,
) -> bool {
    mounts(left, client_ip).into_iter().collect::<BTreeSet<_>>()
        == mounts(right, client_ip)
            .into_iter()
            .collect::<BTreeSet<_>>()
}

pub(crate) fn nfs_mount_layout_matches(
    left: &ClientDescriptor,
    right: &ClientDescriptor,
    client_ip: &str,
) -> bool {
    mounts(left, client_ip)
        .into_iter()
        .filter(ClientMount::is_nfs)
        .collect::<BTreeSet<_>>()
        == mounts(right, client_ip)
            .into_iter()
            .filter(ClientMount::is_nfs)
            .collect::<BTreeSet<_>>()
}

pub(crate) fn has_nfs_mounts(descriptor: &ClientDescriptor, client_ip: &str) -> bool {
    mounts(descriptor, client_ip)
        .iter()
        .any(ClientMount::is_nfs)
}

pub(crate) fn distinct_mount_layouts<'a>(
    descriptors: impl IntoIterator<Item = &'a ClientDescriptor>,
    client_ip: &str,
) -> Vec<ClientDescriptor> {
    let mut layouts = Vec::new();
    for descriptor in descriptors {
        if !layouts
            .iter()
            .any(|existing| mount_layout_matches(existing, descriptor, client_ip))
        {
            layouts.push(descriptor.clone());
        }
    }
    layouts
}

fn retired_mounts(
    previous: &ClientDescriptor,
    next: &ClientDescriptor,
    client_ip: &str,
) -> Vec<ClientMount> {
    let retained = mounts(next, client_ip).into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    mounts(previous, client_ip)
        .into_iter()
        .filter(|mount| !retained.contains(mount) && seen.insert(mount.clone()))
        .collect()
}

fn label(cluster_uuid: &str) -> String {
    format!("org.macluster.client-mount.{cluster_uuid}")
}

fn client_mount_script(
    cluster_uuid: &str,
    descriptor: &ClientDescriptor,
    previous: Option<&ClientDescriptor>,
    client_ip: &str,
) -> String {
    let label = label(cluster_uuid);
    let helper = format!("{HELPER_ROOT}/{label}.sh");
    let plist = format!("{DAEMON_ROOT}/{label}.plist");
    let mut body = "#!/bin/sh\nset -eu\n".to_owned();
    for mount in mounts(descriptor, client_ip)
        .into_iter()
        .filter(ClientMount::is_nfs)
    {
        let source_arg = shell_quote(&mount.source);
        let target_arg = shell_quote(&mount.physical_target);
        if mount.is_nfs() {
            let mounted_target = shell_quote(&format!(" on {} (", mount.physical_target));
            let expected_mount = shell_quote(&format!(
                "{} on {} (nfs",
                mount.source, mount.physical_target
            ));
            body.push_str(&format!(
                "if [ -L {target_arg} ]; then echo 'macluster client mount target is a symlink' >&2; exit 1; fi\nif [ -e {target_arg} ] && [ ! -d {target_arg} ]; then echo 'macluster client mount target is not a directory' >&2; exit 1; fi\nif /sbin/mount | /usr/bin/grep -F {mounted_target} >/dev/null 2>&1; then\n  if ! /sbin/mount | /usr/bin/grep -F {expected_mount} >/dev/null 2>&1; then\n    echo 'macluster client mount target is already mounted from a different source; refusing to replace it' >&2\n    exit 1\n  fi\nelse\n  /bin/mkdir -p {target_arg}\n  /usr/bin/lockf -t {mount_timeout} -k -w {mount_lock} /sbin/mount_nfs -o {mount_options} {source_arg} {target_arg}\nfi\n",
                mount_timeout = NFS_MOUNT_TIMEOUT_SECS,
                mount_lock = NFS_MOUNT_LOCK_PATH,
                mount_options = NFS_MOUNT_OPTIONS,
            ));
        } else if mount.is_smb() {
            let logical = shell_quote(&mount.logical_target);
            let backing_alias = shell_quote(&mount.backing_alias());
            let physical = shell_quote(&mount.physical_target);
            let physical_match = shell_quote(&format!(" on {} (smbfs", mount.physical_target));
            let managed_root = shell_quote(SMB_BACKING_ROOT);
            body.push_str(&format!(
                "if [ -L {logical} ]; then actual=$(/usr/bin/readlink {logical}); if [ \"$actual\" != {backing_alias} ]; then case \"$actual\" in {managed_root}/*) /bin/rm -f {logical} ;; *) echo 'SMB logical mount target points elsewhere' >&2; exit 1 ;; esac; fi; elif [ -e {logical} ]; then [ -d {logical} ] || {{ echo 'SMB logical mount target is not a directory' >&2; exit 1; }}; entries=$(/bin/ls -A {logical}) || exit 1; [ -z \"$entries\" ] || {{ echo 'SMB logical mount target is not empty' >&2; exit 1; }}; /bin/rmdir {logical}; fi\nif /sbin/mount | /usr/bin/grep -F {physical_match} >/dev/null 2>&1; then :; else\n  /bin/mkdir -p {physical}\n  /sbin/mount_smbfs -N -o nopassprompt,nobrowse {source_arg} {physical}\nfi\n/bin/mkdir -p \"$(/usr/bin/dirname {logical})\"\nif [ ! -L {logical} ]; then /bin/ln -s {backing_alias} {logical}; fi\n"
            ));
        }
    }
    let plist_body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>{helper}</string></array><key>RunAtLoad</key><true/><key>StartInterval</key><integer>15</integer><key>ProcessType</key><string>Background</string></dict></plist>\n"
    );
    let mut retired = String::new();
    if let Some(previous) = previous {
        for mount in retired_mounts(previous, descriptor, client_ip)
            .into_iter()
            .filter(ClientMount::is_nfs)
        {
            let target_arg = shell_quote(&mount.physical_target);
            if mount.is_nfs() {
                let expected_mount = shell_quote(&format!(
                    "{} on {} (nfs",
                    mount.source, mount.physical_target
                ));
                retired.push_str(&format!(
                    "if /sbin/mount | /usr/bin/grep -F {expected_mount} >/dev/null 2>&1; then /sbin/umount {target_arg}; fi\n"
                ));
            } else {
                let logical = shell_quote(&mount.logical_target);
                let managed_root = shell_quote(SMB_BACKING_ROOT);
                let physical_match = shell_quote(&format!(" on {} (smbfs", mount.physical_target));
                retired.push_str(&format!(
                    "if [ -L {logical} ]; then actual=$(/usr/bin/readlink {logical}); case \"$actual\" in {managed_root}/*) /bin/rm -f {logical} ;; esac; fi\nif /sbin/mount | /usr/bin/grep -F {physical_match} >/dev/null 2>&1; then /sbin/umount {target_arg}; fi\n"
                ));
            }
        }
    }
    format!(
        "set -eu\n/bin/launchctl bootout system/{label} >/dev/null 2>&1 || true\n{retired}/bin/mkdir -p {HELPER_ROOT}\n/bin/cat > {helper}.next <<'MACLUSTER_HELPER'\n{body}MACLUSTER_HELPER\n/usr/sbin/chown root:wheel {helper}.next\n/bin/chmod 700 {helper}.next\n/bin/mv -f {helper}.next {helper}\n/bin/cat > {plist}.next <<'MACLUSTER_PLIST'\n{plist_body}MACLUSTER_PLIST\n/usr/sbin/chown root:wheel {plist}.next\n/bin/chmod 644 {plist}.next\n/bin/mv -f {plist}.next {plist}\n/bin/launchctl bootstrap system {plist}\n",
        helper = shell_quote(&helper),
        plist = shell_quote(&plist),
    )
}

fn client_remove_script(
    cluster_uuid: &str,
    descriptor: &ClientDescriptor,
    client_ip: &str,
) -> String {
    let label = label(cluster_uuid);
    let helper = format!("{HELPER_ROOT}/{label}.sh");
    let plist = format!("{DAEMON_ROOT}/{label}.plist");
    let mut script = format!(
        "#!/bin/sh\nset -eu\n/bin/launchctl bootout system/{label} >/dev/null 2>&1 || true\n"
    );
    for mount in mounts(descriptor, client_ip)
        .into_iter()
        .filter(ClientMount::is_nfs)
    {
        let target_arg = shell_quote(&mount.physical_target);
        if mount.is_nfs() {
            let expected_mount = shell_quote(&format!(
                "{} on {} (nfs",
                mount.source, mount.physical_target
            ));
            script.push_str(&format!(
                "if /sbin/mount | /usr/bin/grep -F {expected_mount} >/dev/null 2>&1; then /sbin/umount {target_arg}; fi\n"
            ));
        } else {
            let logical = shell_quote(&mount.logical_target);
            let managed_root = shell_quote(SMB_BACKING_ROOT);
            let physical_match = shell_quote(&format!(" on {} (smbfs", mount.physical_target));
            script.push_str(&format!(
                "if [ -L {logical} ]; then actual=$(/usr/bin/readlink {logical}); case \"$actual\" in {managed_root}/*) /bin/rm -f {logical} ;; esac; fi\nif /sbin/mount | /usr/bin/grep -F {physical_match} >/dev/null 2>&1; then /sbin/umount {target_arg}; fi\n"
            ));
        }
    }
    script.push_str(&format!(
        "/bin/rm -f {} {}\n",
        shell_quote(&helper),
        shell_quote(&plist)
    ));
    script
}

fn overlay_targets(descriptor: &ClientDescriptor, client_ip: &str) -> Result<Vec<PathBuf>, String> {
    let mount_table = Command::new("/sbin/mount")
        .output()
        .map_err(|error| format!("cannot inspect current mounts: {error}"))?;
    if !mount_table.status.success() {
        return Err(format!(
            "cannot inspect current mounts: {}",
            String::from_utf8_lossy(&mount_table.stderr).trim()
        ));
    }
    let mount_table = String::from_utf8_lossy(&mount_table.stdout);
    let mut overlays = Vec::new();
    for mount in mounts(descriptor, client_ip) {
        let path = PathBuf::from(if mount.is_smb() {
            &mount.logical_target
        } else {
            &mount.physical_target
        });
        if mount_table_has_exact(&mount_table, &mount) {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "cannot inspect client mount target {}: {error}",
                    path.display()
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            if mount.is_smb() {
                let actual = std::fs::read_link(&path).map_err(|error| {
                    format!(
                        "cannot inspect SMB logical mount target {}: {error}",
                        path.display()
                    )
                })?;
                if actual == std::path::Path::new(&mount.backing_alias()) {
                    // A persisted SMB mount is exposed through this exact
                    // alias. Re-joining must recognize that managed layout.
                    continue;
                }
                if is_managed_smb_backing_alias(&actual) {
                    // A previous cluster/share identity can leave a managed
                    // symlink behind. The mount helper will replace it with
                    // the current backing alias without hiding user files.
                    continue;
                }
                return Err(format!(
                    "SMB logical mount target {} points to {}, not its managed backing path {}",
                    path.display(),
                    actual.display(),
                    mount.backing_alias()
                ));
            }
            return Err(format!(
                "client mount target {} must be a real directory",
                path.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "client mount target {} must be a real directory",
                path.display()
            ));
        }
        let mut entries = std::fs::read_dir(&path).map_err(|error| {
            format!(
                "cannot inspect client mount target {}: {error}",
                path.display()
            )
        })?;
        if entries
            .next()
            .transpose()
            .map_err(|error| {
                format!(
                    "cannot inspect client mount target {}: {error}",
                    path.display()
                )
            })?
            .is_some()
        {
            overlays.push(path);
        }
    }
    Ok(overlays)
}

fn mount_table_has_exact(mount_table: &str, mount: &ClientMount) -> bool {
    mount_table.lines().any(|line| {
        let Some((actual_source, destination)) = line.split_once(" on ") else {
            return false;
        };
        let Some((actual_target, filesystem)) = destination.split_once(" (") else {
            return false;
        };
        let filesystem = filesystem.trim_end_matches(')').split(',').next();
        if mount.is_nfs() {
            actual_source == mount.source
                && actual_target == mount.physical_target
                && filesystem == Some("nfs")
        } else {
            // macOS prints authenticated SMB sources as
            // `//USER@HOST/SHARE`; compare the account and endpoint
            // independently so success does not depend on how the source
            // was normalized by the mount helper.
            let expected = mount.source.trim_start_matches("//");
            let (expected_user, expected_endpoint) = expected
                .rsplit_once('@')
                .map_or((None, expected), |(user, endpoint)| (Some(user), endpoint));
            let (actual_user, actual_endpoint) = actual_source
                .trim_start_matches("//")
                .rsplit_once('@')
                .map_or(
                    (None, actual_source.trim_start_matches("//")),
                    |(user, endpoint)| (Some(user), endpoint),
                );
            actual_target == mount.physical_target
                && filesystem == Some("smbfs")
                && actual_endpoint == expected_endpoint
                && expected_user.is_none_or(|expected| actual_user == Some(expected))
        }
    })
}

fn required_mounts(
    descriptor: &ClientDescriptor,
    required_shares: Option<&[String]>,
    client_ip: &str,
) -> Vec<ClientMount> {
    mounts(descriptor, client_ip)
        .into_iter()
        .filter(|mount| {
            if mount.share_uuid == descriptor.cluster_uuid {
                return true;
            }
            required_shares.is_none_or(|required| {
                descriptor.shares.iter().any(|share| {
                    share.share_uuid == mount.share_uuid
                        && required.iter().any(|id| id == &share.id)
                })
            })
        })
        .collect()
}

fn missing_mounts(
    descriptor: &ClientDescriptor,
    mount_table: &str,
    required_shares: Option<&[String]>,
    client_ip: &str,
) -> Vec<String> {
    required_mounts(descriptor, required_shares, client_ip)
        .into_iter()
        .filter(|mount| !mount_table_has_exact(mount_table, mount))
        .map(|mount| mount.logical_target)
        .collect()
}

fn smb_alias_is_ready(mount: &ClientMount) -> bool {
    if !mount.is_smb() || mount.logical_target == mount.backing_alias() {
        return true;
    }
    std::fs::read_link(&mount.logical_target)
        .is_ok_and(|actual| actual == Path::new(&mount.backing_alias()))
}

pub(crate) fn verify_client_mounts(
    descriptor: &ClientDescriptor,
    required_shares: Option<&[String]>,
    client_ip: &str,
) -> Result<(), String> {
    let mount_table = Command::new("/sbin/mount")
        .output()
        .map_err(|error| format!("cannot inspect current mounts: {error}"))?;
    if !mount_table.status.success() {
        return Err(format!(
            "cannot inspect current mounts: {}",
            String::from_utf8_lossy(&mount_table.stderr).trim()
        ));
    }
    let missing = missing_mounts(
        descriptor,
        &String::from_utf8_lossy(&mount_table.stdout),
        required_shares,
        client_ip,
    );
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "client storage is not mounted from {}; wait for the client mount service to reconnect, or rerun `--join`",
            missing
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn confirm_overlays(descriptor: &ClientDescriptor, client_ip: &str) -> Result<(), String> {
    let overlays = overlay_targets(descriptor, client_ip)?;
    if overlays.is_empty() {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(format!(
            "client mount setup would hide existing files under {}; rerun from a terminal to confirm, or use `--join --control-only`",
            overlays
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    eprintln!(
        "Mounting cluster shares will hide existing local files under: {}",
        overlays
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("The local files remain on disk and reappear after the cluster mount is removed.");
    eprint!("Continue? [y/N]: ");
    use std::io::Write as _;
    io::stderr()
        .flush()
        .map_err(|error| format!("cannot display mount confirmation: {error}"))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("cannot read mount confirmation: {error}"))?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err("client mount setup cancelled; no shares were mounted".into())
    }
}

pub(crate) fn install_client_mounts(
    cluster_uuid: &str,
    descriptor: &ClientDescriptor,
    client_ip: &str,
) -> Result<(), String> {
    if !has_nfs_mounts(descriptor, client_ip) {
        return Ok(());
    }
    confirm_overlays(descriptor, client_ip)?;
    run_client_mount_script(client_mount_script(
        cluster_uuid,
        descriptor,
        None,
        client_ip,
    ))
}

pub(crate) fn replace_client_mounts(
    cluster_uuid: &str,
    previous: &ClientDescriptor,
    descriptor: &ClientDescriptor,
    client_ip: &str,
) -> Result<(), String> {
    for share in previous.shares.iter().filter(|share| {
        share.protocol == "smb"
            && !descriptor
                .shares
                .iter()
                .any(|current| current.protocol == "smb" && current == *share)
    }) {
        crate::node_admin::unmount_client_smb_share(share)?;
    }
    if !has_nfs_mounts(previous, client_ip) && !has_nfs_mounts(descriptor, client_ip) {
        return Ok(());
    }
    confirm_overlays(descriptor, client_ip)?;
    run_client_mount_script(client_mount_script(
        cluster_uuid,
        descriptor,
        Some(previous),
        client_ip,
    ))
}

fn run_client_mount_script(script: String) -> Result<(), String> {
    let status = std::process::Command::new("/usr/bin/sudo")
        .args(["/bin/sh", "-c", &script])
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "client mount setup exited with {}",
            status.code().unwrap_or(1)
        ))
    }
}

pub(crate) fn remove_client_mounts(
    cluster_uuid: &str,
    descriptor: &ClientDescriptor,
    client_ip: &str,
) -> Result<(), String> {
    let mut smb_cleanup_error = None;
    for share in descriptor
        .shares
        .iter()
        .filter(|share| share.protocol == "smb" && share.server_host != client_ip)
    {
        if let Err(error) = crate::node_admin::unmount_client_smb_share(share) {
            smb_cleanup_error.get_or_insert_with(|| error);
        }
    }
    if has_nfs_mounts(descriptor, client_ip) {
        let script = client_remove_script(cluster_uuid, descriptor, client_ip);
        let status = std::process::Command::new("/usr/bin/sudo")
            .args(["/bin/sh", "-c", &script])
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!(
                "client mount removal exited with {}",
                status.code().unwrap_or(1)
            ));
        }
    }
    smb_cleanup_error.map_or(Ok(()), Err)
}

pub(crate) fn ensure_required_smb_mounts(
    descriptor: &ClientDescriptor,
    required_shares: Option<&[String]>,
    client_ip: &str,
) -> Result<(), String> {
    let mount_table = Command::new("/sbin/mount")
        .output()
        .map_err(|error| format!("cannot inspect current mounts: {error}"))?;
    if !mount_table.status.success() {
        return Err(format!(
            "cannot inspect current mounts: {}",
            String::from_utf8_lossy(&mount_table.stderr).trim()
        ));
    }
    let mount_table = String::from_utf8_lossy(&mount_table.stdout);
    for mount in required_mounts(descriptor, required_shares, client_ip) {
        if !mount.is_smb()
            || (mount_table_has_exact(&mount_table, &mount) && smb_alias_is_ready(&mount))
        {
            continue;
        }
        let share = descriptor
            .shares
            .iter()
            .find(|share| share.share_uuid == mount.share_uuid)
            .ok_or_else(|| {
                format!(
                    "SMB share {} is missing from the controller descriptor",
                    mount.share_uuid
                )
            })?;
        crate::node_admin::mount_client_smb_share(&descriptor.cluster_uuid, share).map_err(
            |error| {
                format!(
                    "cannot mount required SMB storage {} at {}: {error}",
                    share.id, share.mount_root
                )
            },
        )?;
    }
    verify_client_mounts(descriptor, required_shares, client_ip)
}

#[cfg(test)]
mod tests {
    use super::{
        client_mount_script, client_remove_script, distinct_mount_layouts, missing_mounts,
        mount_layout_matches, overlay_targets, retired_mounts,
    };
    use crate::nfs_recovery::NFS_MOUNT_OPTIONS;
    use macluster_protocol::control::{
        ClientDescriptor, ClientQueueDescriptor, ClientShareDescriptor,
    };
    use macluster_protocol::identifiers::Id128;
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    fn descriptor() -> ClientDescriptor {
        ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            default_queue: "default".parse().unwrap(),
            config_generation: 1,
            controller_build_id: "test".into(),
            controller_binary: String::new(),
            controller_uid: 501,
            capabilities: vec![macluster_protocol::control::MULTI_ENTRY_CLIENT_FEATURE.into()],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![ClientShareDescriptor {
                id: "tools".into(),
                server: "login".parse().unwrap(),
                protocol: "nfs".into(),
                server_host: "192.0.2.1".into(),
                source_root: "/opt/homebrew".into(),
                mount_root: "/opt/homebrew".into(),
                share_uuid: "82d02835-f6ab-52b4-aaab-f90cafde9981".into(),
                smb_user: None,
            }],
            queues: vec![ClientQueueDescriptor {
                name: "default".parse().unwrap(),
                nodes: vec![],
            }],
        }
    }

    #[test]
    fn mount_layout_ignores_queue_and_generation_metadata() {
        let mut next = descriptor();
        next.config_generation = 9;
        next.controller_build_id = "new-build".into();
        next.default_queue = "batch".parse().unwrap();
        next.queues[0].name = "batch".parse().unwrap();
        assert!(mount_layout_matches(&descriptor(), &next, "192.0.2.10"));

        next.primary_source_root = "/Users/Shared/macluster-v2".into();
        assert!(!mount_layout_matches(&descriptor(), &next, "192.0.2.10"));
    }

    #[test]
    fn distinct_mount_layouts_keeps_each_source_for_cleanup() {
        let first = descriptor();
        let mut second = first.clone();
        second.primary_source_root = "/Users/Shared/macluster-v2".into();
        assert_eq!(
            distinct_mount_layouts([&first, &second], "192.0.2.10"),
            vec![first, second]
        );
    }

    #[test]
    fn mount_script_contains_exact_primary_and_named_sources() {
        let script = client_mount_script(
            "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            &descriptor(),
            None,
            "192.0.2.10",
        );
        assert!(script.contains("192.0.2.1:/Users/Shared/macluster"));
        assert!(script.contains("192.0.2.1:/opt/homebrew"));
        assert!(script.contains("/Library/LaunchDaemons/org.macluster.client-mount."));
        assert!(script.contains(&format!("/sbin/mount_nfs -o {NFS_MOUNT_OPTIONS}")));
    }

    #[test]
    fn client_does_not_mount_storage_hosted_on_its_own_address() {
        let mut descriptor = descriptor();
        descriptor.shares.push(ClientShareDescriptor {
            id: "local-disk".into(),
            server: "worker".parse().unwrap(),
            protocol: "nfs".into(),
            server_host: "192.0.2.10".into(),
            source_root: "/Volumes/data".into(),
            mount_root: "/Volumes/data".into(),
            share_uuid: "55fb9b02-ce96-5a69-8ad3-356563eff27b".into(),
            smb_user: None,
        });
        let script = client_mount_script(
            "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            &descriptor,
            None,
            "192.0.2.10",
        );
        assert!(!script.contains("192.0.2.10:/Volumes/data"));
        assert!(script.contains("192.0.2.1:/Users/Shared/macluster"));
        assert_eq!(missing_mounts(&descriptor, "", None, "192.0.2.10").len(), 2);
    }

    #[test]
    fn smb_shares_are_not_mounted_by_the_privileged_nfs_service() {
        let mut descriptor = descriptor();
        descriptor.shares.push(ClientShareDescriptor {
            id: "smb-project".into(),
            server: "nas".parse().unwrap(),
            protocol: "smb".into(),
            server_host: "192.0.2.20".into(),
            source_root: "/data/project".into(),
            mount_root: "/Volumes/project".into(),
            share_uuid: "928e8976-c946-509d-9e62-a3ef787664b7".into(),
            smb_user: Some("smb-user".into()),
        });
        let script = client_mount_script(
            "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            &descriptor,
            None,
            "192.0.2.10",
        );

        assert!(!script.contains("mount_smbfs"));
        assert!(!script.contains("//smb-user@192.0.2.20/data"));
        assert!(!script.contains("/Volumes/project"));
        assert_eq!(
            missing_mounts(
                &descriptor,
                "192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs)\n",
                None,
                "192.0.2.10",
            )
            .len(),
            1
        );
        let wrong_source = "//other-server/data on /Users/Shared/.macluster-mounts/928e8976-c946-509d-9e62-a3ef787664b7 (smbfs, nodev)\n192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs)\n";
        assert_eq!(
            missing_mounts(&descriptor, wrong_source, None, "192.0.2.10"),
            vec!["/Volumes/project".to_owned()]
        );
        let mounted_smb = "//smb-user@192.0.2.20/data on /Users/Shared/.macluster-mounts/928e8976-c946-509d-9e62-a3ef787664b7 (smbfs, nodev)\n192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs)\n";
        assert!(
            missing_mounts(&descriptor, mounted_smb, None, "192.0.2.10").is_empty(),
            "authenticated SMB source must match after both actual and expected usernames are normalized"
        );
    }

    #[test]
    fn smb_mount_rejects_endpoint_suffix_match() {
        let mut descriptor = descriptor();
        descriptor.shares.push(ClientShareDescriptor {
            id: "smb-project".into(),
            server: "nas".parse().unwrap(),
            protocol: "smb".into(),
            server_host: "192.0.2.20".into(),
            source_root: "/data/project".into(),
            mount_root: "/Volumes/project".into(),
            share_uuid: "928e8976-c946-509d-9e62-a3ef787664b7".into(),
            smb_user: Some("smb-user".into()),
        });
        let suffix_only_match = "//smb-user@evil-192.0.2.20/data on /Users/Shared/.macluster-mounts/928e8976-c946-509d-9e62-a3ef787664b7 (smbfs, nodev)\n192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs)\n";
        assert_eq!(
            missing_mounts(&descriptor, suffix_only_match, None, "192.0.2.10"),
            vec!["/Volumes/project".to_owned()],
            "SMB host/share matching must not accept a source whose endpoint only shares a suffix"
        );
    }

    #[test]
    fn remove_script_unloads_only_its_cluster_daemon() {
        let script = client_remove_script(
            "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            &descriptor(),
            "192.0.2.10",
        );
        assert!(script.contains("org.macluster.client-mount.f779bcf5-ea85-5caa-9579-74b395f3cce5"));
        assert!(script.contains("/Users/Shared/macluster"));
        assert!(script.contains("/opt/homebrew"));
    }

    #[test]
    fn mount_helper_is_valid_posix_shell() {
        let script = client_mount_script(
            "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            &descriptor(),
            None,
            "192.0.2.10",
        );
        let helper = script
            .split_once("<<'MACLUSTER_HELPER'\n")
            .and_then(|(_, remainder)| remainder.split_once("\nMACLUSTER_HELPER"))
            .map(|(helper, _)| helper)
            .expect("outer mount script contains a helper heredoc");
        let output = Command::new("/bin/sh")
            .args(["-n", "-c", helper])
            .output()
            .expect("run shell syntax check");
        assert!(
            output.status.success(),
            "mount helper is not valid POSIX shell:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn mount_helper_refuses_a_target_mounted_from_the_wrong_source() {
        let root = std::env::temp_dir().join(format!("macluster-client-mount-{}", Id128::random()));
        let target = root.join("shared");
        fs::create_dir_all(&target).unwrap();
        let fake_mount = root.join("mount");
        let fake_mount_nfs = root.join("mount_nfs");
        let marker = root.join("mount-nfs-called");
        fs::write(
            &fake_mount,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '198.51.100.9:/wrong on {} (nfs, nodev)'\n",
                target.display()
            ),
        )
        .unwrap();
        fs::write(
            &fake_mount_nfs,
            format!("#!/bin/sh\nprintf called > '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&fake_mount, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&fake_mount_nfs, fs::Permissions::from_mode(0o700)).unwrap();

        let mut descriptor = descriptor();
        descriptor.primary_mount_root = target.to_string_lossy().into_owned();
        descriptor.primary_source_root = root.join("source").to_string_lossy().into_owned();
        descriptor.shares.clear();
        let script = client_mount_script(
            "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            &descriptor,
            None,
            "192.0.2.10",
        );
        let helper = script
            .split_once("<<'MACLUSTER_HELPER'\n")
            .and_then(|(_, remainder)| remainder.split_once("\nMACLUSTER_HELPER"))
            .map(|(helper, _)| helper)
            .expect("outer mount script contains a helper heredoc")
            .replace("/sbin/mount_nfs", &fake_mount_nfs.to_string_lossy())
            .replace("/sbin/mount", &fake_mount.to_string_lossy());
        let output = Command::new("/bin/sh")
            .args(["-c", &helper])
            .output()
            .expect("run generated mount helper");
        assert!(
            !output.status.success(),
            "mount helper must not replace a foreign NFS source"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("different source"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !marker.exists(),
            "a foreign NFS mount must not be unmounted or replaced"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nonempty_local_mount_targets_require_explicit_overlay_approval() {
        let root =
            std::env::temp_dir().join(format!("macluster-client-overlay-{}", Id128::random()));
        let target = root.join("shared");
        fs::create_dir_all(&target).unwrap();
        let retained = target.join("local-file");
        fs::write(&retained, "keep").unwrap();
        let mut descriptor = descriptor();
        descriptor.primary_mount_root = target.to_string_lossy().into_owned();
        descriptor.shares.clear();
        assert_eq!(
            overlay_targets(&descriptor, "192.0.2.10").unwrap(),
            vec![target.clone()]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn smb_logical_symlink_is_accepted_only_when_it_points_to_backing_storage() {
        let root =
            std::env::temp_dir().join(format!("macluster-client-smb-overlay-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let logical = root.join("project");
        let share_uuid = "9e2d7ea7-819a-5e02-b530-e133d971c10c";
        let expected = format!("/Users/Shared/.macluster-mounts/{share_uuid}/project/nested");
        std::os::unix::fs::symlink(&expected, &logical).unwrap();
        let mut descriptor = descriptor();
        descriptor.primary_source_host = "192.0.2.10".into();
        descriptor.shares = vec![ClientShareDescriptor {
            id: "smb-project".into(),
            server: "nas".parse().unwrap(),
            protocol: "smb".into(),
            server_host: "192.0.2.20".into(),
            source_root: "/data/project/nested".into(),
            mount_root: logical.to_string_lossy().into_owned(),
            share_uuid: share_uuid.into(),
            smb_user: Some("smb-user".into()),
        }];

        assert!(
            overlay_targets(&descriptor, "192.0.2.10")
                .unwrap()
                .is_empty()
        );

        fs::remove_file(&logical).unwrap();
        let stale =
            "/Users/Shared/.macluster-mounts/fa87abfd-de27-5001-a250-5bd4d94365eb/project/nested";
        std::os::unix::fs::symlink(stale, &logical).unwrap();
        assert!(
            overlay_targets(&descriptor, "192.0.2.10")
                .unwrap()
                .is_empty(),
            "a stale macluster-managed SMB alias is safe to replace"
        );
        fs::remove_file(&logical).unwrap();
        std::os::unix::fs::symlink("/tmp/unrelated", &logical).unwrap();
        assert!(
            overlay_targets(&descriptor, "192.0.2.10").is_err(),
            "an unrelated SMB logical symlink must not be replaced"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_removed_or_moved_share_is_retired_by_the_next_mount_update() {
        let old = descriptor();
        let mut next = old.clone();
        next.shares[0].source_root = "/opt/homebrew-next".into();
        let retired = retired_mounts(&old, &next, "192.0.2.10");
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].source, "192.0.2.1:/opt/homebrew");
        assert_eq!(retired[0].logical_target, "/opt/homebrew");
        next.shares.clear();
        let retired = retired_mounts(&old, &next, "192.0.2.10");
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].logical_target, "/opt/homebrew");
    }

    #[test]
    fn storage_verification_requires_every_exact_source_and_target() {
        let descriptor = descriptor();
        assert_eq!(missing_mounts(&descriptor, "", None, "192.0.2.10").len(), 2);
        let mounted = "192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs, nodev)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs, nodev)\n";
        assert!(missing_mounts(&descriptor, mounted, None, "192.0.2.10").is_empty());
        let wrong = "198.51.100.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs)\n";
        assert_eq!(
            missing_mounts(&descriptor, wrong, None, "192.0.2.10"),
            vec!["/Users/Shared/macluster".to_owned()]
        );
        let prefix_collision = "x192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew-old (nfs)\n";
        assert_eq!(
            missing_mounts(&descriptor, prefix_collision, None, "192.0.2.10").len(),
            2
        );
        assert_eq!(
            missing_mounts(
                &descriptor,
                "192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n",
                Some(&[]),
                "192.0.2.10",
            )
            .len(),
            0
        );
    }
}
