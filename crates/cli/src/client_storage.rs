use macluster_protocol::control::ClientDescriptor;
use std::{
    collections::BTreeSet,
    io::{self, IsTerminal},
    path::PathBuf,
    process::Command,
};

use crate::node_admin::shell_quote;

const HELPER_ROOT: &str = "/Library/PrivilegedHelperTools";
const DAEMON_ROOT: &str = "/Library/LaunchDaemons";

fn mounts(descriptor: &ClientDescriptor) -> Vec<(String, String)> {
    let mut mounts = vec![(
        format!(
            "{}:{}",
            descriptor.primary_source_host, descriptor.primary_source_root
        ),
        descriptor.primary_mount_root.clone(),
    )];
    mounts.extend(descriptor.shares.iter().map(|share| {
        (
            format!("{}:{}", share.server_host, share.source_root),
            share.mount_root.clone(),
        )
    }));
    mounts
}

pub(crate) fn mount_layout_matches(left: &ClientDescriptor, right: &ClientDescriptor) -> bool {
    mounts(left).into_iter().collect::<BTreeSet<_>>()
        == mounts(right).into_iter().collect::<BTreeSet<_>>()
}

pub(crate) fn distinct_mount_layouts<'a>(
    descriptors: impl IntoIterator<Item = &'a ClientDescriptor>,
) -> Vec<ClientDescriptor> {
    let mut layouts = Vec::new();
    for descriptor in descriptors {
        if !layouts
            .iter()
            .any(|existing| mount_layout_matches(existing, descriptor))
        {
            layouts.push(descriptor.clone());
        }
    }
    layouts
}

fn retired_mounts(previous: &ClientDescriptor, next: &ClientDescriptor) -> Vec<(String, String)> {
    let retained = mounts(next).into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    mounts(previous)
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
) -> String {
    let label = label(cluster_uuid);
    let helper = format!("{HELPER_ROOT}/{label}.sh");
    let plist = format!("{DAEMON_ROOT}/{label}.plist");
    let mut body = "#!/bin/sh\nset -eu\n".to_owned();
    for (source, target) in mounts(descriptor) {
        let source_arg = shell_quote(&source);
        let target_arg = shell_quote(&target);
        let mounted_target = shell_quote(&format!(" on {target} ("));
        let expected_mount = shell_quote(&format!("{source} on {target} (nfs"));
        body.push_str(&format!(
            "if [ -L {target_arg} ]; then echo 'macluster client mount target is a symlink' >&2; exit 1; fi\nif [ -e {target_arg} ] && [ ! -d {target_arg} ]; then echo 'macluster client mount target is not a directory' >&2; exit 1; fi\nif /sbin/mount | /usr/bin/grep -F {mounted_target} >/dev/null 2>&1; then\n  if ! /sbin/mount | /usr/bin/grep -F {expected_mount} >/dev/null 2>&1; then\n    echo 'macluster client mount target is already mounted from a different source; refusing to replace it' >&2\n    exit 1\n  fi\nelse\n  /bin/mkdir -p {target_arg}\n  /sbin/mount_nfs -o resvport {source_arg} {target_arg}\nfi\n"
        ));
    }
    let plist_body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>{helper}</string></array><key>RunAtLoad</key><true/><key>StartInterval</key><integer>5</integer><key>ProcessType</key><string>Background</string></dict></plist>\n"
    );
    let mut retired = String::new();
    if let Some(previous) = previous {
        for (source, target) in retired_mounts(previous, descriptor) {
            let target_arg = shell_quote(&target);
            let expected_mount = shell_quote(&format!("{source} on {target} (nfs"));
            retired.push_str(&format!(
                "if /sbin/mount | /usr/bin/grep -F {expected_mount} >/dev/null 2>&1; then /sbin/umount {target_arg}; fi\n"
            ));
        }
    }
    format!(
        "set -eu\n/bin/launchctl bootout system/{label} >/dev/null 2>&1 || true\n{retired}/bin/mkdir -p {HELPER_ROOT}\n/bin/cat > {helper}.next <<'MACLUSTER_HELPER'\n{body}MACLUSTER_HELPER\n/usr/sbin/chown root:wheel {helper}.next\n/bin/chmod 700 {helper}.next\n/bin/mv -f {helper}.next {helper}\n/bin/cat > {plist}.next <<'MACLUSTER_PLIST'\n{plist_body}MACLUSTER_PLIST\n/usr/sbin/chown root:wheel {plist}.next\n/bin/chmod 644 {plist}.next\n/bin/mv -f {plist}.next {plist}\n/bin/launchctl bootstrap system {plist}\n",
        helper = shell_quote(&helper),
        plist = shell_quote(&plist),
    )
}

fn client_remove_script(cluster_uuid: &str, descriptor: &ClientDescriptor) -> String {
    let label = label(cluster_uuid);
    let helper = format!("{HELPER_ROOT}/{label}.sh");
    let plist = format!("{DAEMON_ROOT}/{label}.plist");
    let mut script = format!(
        "#!/bin/sh\nset -eu\n/bin/launchctl bootout system/{label} >/dev/null 2>&1 || true\n"
    );
    for (source, target) in mounts(descriptor) {
        let target_arg = shell_quote(&target);
        let expected_mount = shell_quote(&format!("{source} on {target} (nfs"));
        script.push_str(&format!(
            "if /sbin/mount | /usr/bin/grep -F {expected_mount} >/dev/null 2>&1; then /sbin/umount {target_arg}; fi\n"
        ));
    }
    script.push_str(&format!(
        "/bin/rm -f {} {}\n",
        shell_quote(&helper),
        shell_quote(&plist)
    ));
    script
}

fn overlay_targets(descriptor: &ClientDescriptor) -> Result<Vec<PathBuf>, String> {
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
    for (source, target) in mounts(descriptor) {
        let path = PathBuf::from(&target);
        if mount_table_has_exact(&mount_table, &source, &target) {
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
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
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

fn mount_table_has_exact(mount_table: &str, source: &str, target: &str) -> bool {
    mount_table.lines().any(|line| {
        let Some((actual_source, destination)) = line.split_once(" on ") else {
            return false;
        };
        let Some((actual_target, filesystem)) = destination.split_once(" (") else {
            return false;
        };
        actual_source == source
            && actual_target == target
            && filesystem.trim_end_matches(')').split(',').next() == Some("nfs")
    })
}

fn required_mounts(
    descriptor: &ClientDescriptor,
    required_shares: Option<&[String]>,
) -> Vec<(String, String)> {
    let mut required = vec![(
        format!(
            "{}:{}",
            descriptor.primary_source_host, descriptor.primary_source_root
        ),
        descriptor.primary_mount_root.clone(),
    )];
    required.extend(
        descriptor
            .shares
            .iter()
            .filter(|share| {
                required_shares.is_none_or(|required| required.iter().any(|id| id == &share.id))
            })
            .map(|share| {
                (
                    format!("{}:{}", share.server_host, share.source_root),
                    share.mount_root.clone(),
                )
            }),
    );
    required
}

fn missing_mounts(
    descriptor: &ClientDescriptor,
    mount_table: &str,
    required_shares: Option<&[String]>,
) -> Vec<(String, String)> {
    required_mounts(descriptor, required_shares)
        .into_iter()
        .filter(|(source, target)| !mount_table_has_exact(mount_table, source, target))
        .collect()
}

pub(crate) fn verify_client_mounts(
    descriptor: &ClientDescriptor,
    required_shares: Option<&[String]>,
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
    );
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "client storage is not mounted from {}; wait for the client mount service to reconnect, or rerun `--join`",
            missing
                .iter()
                .map(|(_, target)| target.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn confirm_overlays(descriptor: &ClientDescriptor) -> Result<(), String> {
    let overlays = overlay_targets(descriptor)?;
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
) -> Result<(), String> {
    confirm_overlays(descriptor)?;
    run_client_mount_script(client_mount_script(cluster_uuid, descriptor, None))
}

pub(crate) fn replace_client_mounts(
    cluster_uuid: &str,
    previous: &ClientDescriptor,
    descriptor: &ClientDescriptor,
) -> Result<(), String> {
    confirm_overlays(descriptor)?;
    run_client_mount_script(client_mount_script(
        cluster_uuid,
        descriptor,
        Some(previous),
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
) -> Result<(), String> {
    let script = client_remove_script(cluster_uuid, descriptor);
    let status = std::process::Command::new("/usr/bin/sudo")
        .args(["/bin/sh", "-c", &script])
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "client mount removal exited with {}",
            status.code().unwrap_or(1)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        client_mount_script, client_remove_script, distinct_mount_layouts, missing_mounts,
        mount_layout_matches, overlay_targets, retired_mounts,
    };
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
            controller_uid: 501,
            capabilities: vec![macluster_protocol::control::MULTI_ENTRY_CLIENT_FEATURE.into()],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![ClientShareDescriptor {
                id: "tools".into(),
                server: "login".parse().unwrap(),
                server_host: "192.0.2.1".into(),
                source_root: "/opt/homebrew".into(),
                mount_root: "/opt/homebrew".into(),
                share_uuid: "82d02835-f6ab-52b4-aaab-f90cafde9981".into(),
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
        assert!(mount_layout_matches(&descriptor(), &next));

        next.primary_source_root = "/Users/Shared/macluster-v2".into();
        assert!(!mount_layout_matches(&descriptor(), &next));
    }

    #[test]
    fn distinct_mount_layouts_keeps_each_source_for_cleanup() {
        let first = descriptor();
        let mut second = first.clone();
        second.primary_source_root = "/Users/Shared/macluster-v2".into();
        assert_eq!(
            distinct_mount_layouts([&first, &second]),
            vec![first, second]
        );
    }

    #[test]
    fn mount_script_contains_exact_primary_and_named_sources() {
        let script =
            client_mount_script("f779bcf5-ea85-5caa-9579-74b395f3cce5", &descriptor(), None);
        assert!(script.contains("192.0.2.1:/Users/Shared/macluster"));
        assert!(script.contains("192.0.2.1:/opt/homebrew"));
        assert!(script.contains("/Library/LaunchDaemons/org.macluster.client-mount."));
        assert!(script.contains("/sbin/mount_nfs -o resvport"));
    }

    #[test]
    fn remove_script_unloads_only_its_cluster_daemon() {
        let script = client_remove_script("f779bcf5-ea85-5caa-9579-74b395f3cce5", &descriptor());
        assert!(script.contains("org.macluster.client-mount.240edfcc"));
        assert!(script.contains("/Users/Shared/macluster"));
        assert!(script.contains("/opt/homebrew"));
    }

    #[test]
    fn mount_helper_is_valid_posix_shell() {
        let script =
            client_mount_script("f779bcf5-ea85-5caa-9579-74b395f3cce5", &descriptor(), None);
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
        let script = client_mount_script("f779bcf5-ea85-5caa-9579-74b395f3cce5", &descriptor, None);
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
        assert_eq!(overlay_targets(&descriptor).unwrap(), vec![target.clone()]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_removed_or_moved_share_is_retired_by_the_next_mount_update() {
        let old = descriptor();
        let mut next = old.clone();
        next.shares[0].source_root = "/opt/homebrew-next".into();
        assert_eq!(
            retired_mounts(&old, &next),
            vec![("192.0.2.1:/opt/homebrew".into(), "/opt/homebrew".into())]
        );
        next.shares.clear();
        assert_eq!(
            retired_mounts(&old, &next),
            vec![("192.0.2.1:/opt/homebrew".into(), "/opt/homebrew".into())]
        );
    }

    #[test]
    fn storage_verification_requires_every_exact_source_and_target() {
        let descriptor = descriptor();
        assert_eq!(missing_mounts(&descriptor, "", None).len(), 2);
        let mounted = "192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs, nodev)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs, nodev)\n";
        assert!(missing_mounts(&descriptor, mounted, None).is_empty());
        let wrong = "198.51.100.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew (nfs)\n";
        assert_eq!(
            missing_mounts(&descriptor, wrong, None),
            vec![(
                "192.0.2.1:/Users/Shared/macluster".into(),
                "/Users/Shared/macluster".into()
            )]
        );
        let prefix_collision = "x192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n192.0.2.1:/opt/homebrew on /opt/homebrew-old (nfs)\n";
        assert_eq!(missing_mounts(&descriptor, prefix_collision, None).len(), 2);
        assert_eq!(
            missing_mounts(
                &descriptor,
                "192.0.2.1:/Users/Shared/macluster on /Users/Shared/macluster (nfs)\n",
                Some(&[]),
            )
            .len(),
            0
        );
    }
}
