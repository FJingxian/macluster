//! Conservative, resumable reuse of a former login node's primary directory.
use super::*;

pub(super) struct PrimaryReusePlan {
    pub request: ClientMountRequest,
    pub preparation: String,
    pub backup_path: PathBuf,
}

fn backup_path(root: &Path, namespace: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}.macluster-preserved-{namespace}",
        root.display()
    ))
}

fn proof_text(root: &Path, namespace: &str) -> String {
    format!(
        "MACLUSTER_PRIMARY_REUSE_V1\n{namespace}\n{}\n",
        root.display()
    )
}

// Reject child mounts too: renaming a directory containing one would hide a
// mounted filesystem, and an unmount must never detach an ambiguous target.
fn old_mount(table: &str, root: &Path, backup: &Path) -> Result<Option<String>, String> {
    let root = root.to_string_lossy();
    let backup = backup.to_string_lossy();
    let mut found = None;
    for line in table.lines() {
        let Some((source, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((target, options)) = rest.rsplit_once(" (") else {
            continue;
        };
        if target.starts_with(&format!("{root}/"))
            || target == backup
            || target.starts_with(&format!("{backup}/"))
        {
            return Err("primary reuse refuses nested or preservation-path mounts".into());
        }
        if target != root {
            continue;
        }
        if found.is_some()
            || options.split([',', ')']).next() != Some("nfs")
            || !source.contains(":/")
        {
            return Err("primary reuse requires one unambiguous NFS mount; the existing mount was left untouched".into());
        }
        found = Some(source.to_owned());
    }
    Ok(found)
}

fn retire_exports(original: &str, root: &Path, marker: Option<&str>) -> Result<String, String> {
    let root = root.to_string_lossy();
    let lines: Vec<_> = original.lines().collect();
    let mut retained = Vec::new();
    let mut index = 0;
    let mut changed = false;
    while index < lines.len() {
        let line = lines[index];
        let entry_index = if line.starts_with("# macluster-managed ") {
            index + 1
        } else {
            index
        };
        let entry = lines.get(entry_index).copied().unwrap_or_default();
        let tokens: Vec<_> = entry
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        let touches_root = tokens
            .iter()
            .filter(|token| token.starts_with('/'))
            .any(|path| {
                *path == root
                    || path.starts_with(&format!("{root}/"))
                    || root.starts_with(&format!("{path}/"))
            });
        if touches_root {
            let fields: Vec<_> = line.split_whitespace().collect();
            if entry_index != index + 1
                || fields.len() != 4
                || fields[0] != "#"
                || fields[1] != "macluster-managed"
                || marker != Some(fields[2])
                || fields[3].is_empty()
                || tokens.len() != 2
                || tokens[0] != root
                || tokens[1].parse::<Ipv4Addr>().is_err()
                || entry != format!("{} {}", root, tokens[1])
            {
                return Err(format!(
                    "export touching {root} is not an exact macluster-managed pair for its visible share UUID; exports were left untouched"
                ));
            }
            changed = true;
            index += 2;
        } else {
            retained.push(line);
            index += 1;
        }
    }
    if !changed {
        return Ok(original.to_owned());
    }
    Ok(if retained.is_empty() {
        String::new()
    } else {
        retained.join("\n") + "\n"
    })
}

fn path_checks() -> &'static str {
    r#"current=''
old_ifs=$IFS; IFS='/'; set -- ${root#/}; IFS=$old_ifs
for part do
  current="$current/$part"
  [ ! -L "$current" ] || { echo "symlink in primary path: $current" >&2; exit 1; }
  if [ -e "$current" ] && [ ! -d "$current" ]; then echo 'primary path is not a directory' >&2; exit 1; fi
done
[ ! -L "$backup" ] && [ ! -L "$proof" ] || { echo 'preservation path is a symlink' >&2; exit 1; }
if [ -e "$backup" ] && [ ! -d "$backup" ]; then echo 'preservation path is not a directory' >&2; exit 1; fi
if [ -e "$proof" ]; then
  [ -f "$proof" ] && [ "$(/usr/bin/stat -f '%u:%Lp' "$proof")" = '0:600' ] || { echo 'preservation proof is not private and root-owned' >&2; exit 1; }
fi
if [ -e "$backup" ] && [ ! -f "$proof" ]; then echo 'occupied preservation path has no ownership proof' >&2; exit 1; fi
"#
}

fn variables(root: &Path, namespace: &str) -> String {
    let backup = backup_path(root, namespace);
    format!(
        "root={}\nbackup={}\nproof={}\n",
        shell_quote(&root.to_string_lossy()),
        shell_quote(&backup.to_string_lossy()),
        shell_quote(&format!("{}.owner", backup.display()))
    )
}

fn mount_check(source: Option<&str>, root: &Path, backup: &Path) -> String {
    // Compare a normalized exact mount record, and reject nested targets.
    let awk = r#"{ s=index($0," on "); if(!s) next; src=substr($0,1,s-1); r=substr($0,s+4); p=index(r," ("); if(!p) next; t=substr(r,1,p-1); f=substr(r,p+2); sub(/[,)].*/,"",f); if(t==backup || index(t,backup "/")==1 || index(t,root "/")==1) bad=1; if(t==root) {count++; actual=src; fs=f;} } END {if(bad || count>1 || (count==1 && (fs!="nfs" || actual!=source))) exit 1; if(count==1) print "mounted"; else print "none";}"#;
    format!(
        "mount_state=$(/sbin/mount | /usr/bin/awk -v root={} -v backup={} -v source={} {}) || {{ echo 'primary mount changed or is unmanaged; refusing reuse' >&2; exit 1; }}\n",
        shell_quote(&root.to_string_lossy()),
        shell_quote(&backup.to_string_lossy()),
        shell_quote(source.unwrap_or("")),
        shell_quote(awk)
    )
}

fn preparation_script(
    root: &Path,
    namespace: &str,
    old_source: Option<&str>,
    marker: Option<&str>,
    fingerprint: &str,
    export_commands: &str,
) -> String {
    let backup = backup_path(root, namespace);
    let expected_proof = shell_quote(proof_text(root, namespace).trim_end());
    let mut script = String::from("set -eu\n");
    script.push_str(&variables(root, namespace));
    script.push_str(path_checks());
    script.push_str(&format!("expected_proof={expected_proof}\nif [ -e \"$proof\" ]; then printf '%s\\n' \"$expected_proof\" | /usr/bin/cmp - \"$proof\" >/dev/null 2>&1 || {{ echo 'preservation proof does not match this enrollment' >&2; exit 1; }}; fi\n"));
    script.push_str(&mount_check(old_source, root, &backup));
    if let Some(marker) = marker {
        script.push_str(&format!("if [ \"$mount_state\" = mounted ]; then [ ! -L \"$root/.macluster-share-id\" ] && [ -f \"$root/.macluster-share-id\" ] && [ \"$(/bin/cat \"$root/.macluster-share-id\")\" = {} ] || {{ echo 'old share marker changed' >&2; exit 1; }}; fi\n", shell_quote(marker)));
    }
    // A completed rename is recognized by proof + backup, never by a name alone.
    if old_source.is_none() {
        script.push_str(&format!("if [ ! -e \"$backup\" ] && [ \"$mount_state\" = none ] && [ -e \"$root\" ]; then [ \"$(/usr/bin/stat -f '%d:%i' \"$root\")\" = {} ] || {{ echo 'primary directory changed after inspection' >&2; exit 1; }}; fi\n", shell_quote(fingerprint)));
    }
    script.push_str("if [ -e \"$backup\" ] && [ \"$mount_state\" = none ] && [ -d \"$root\" ]; then entries=$(/bin/ls -A \"$root\") || exit 1; [ -z \"$entries\" ] || { echo 'primary target occupied; preserved data left untouched' >&2; exit 1; }; fi\n");
    script.push_str(export_commands);
    script.push_str(&mount_check(old_source, root, &backup));
    if let Some(marker) = marker {
        script.push_str(&format!("if [ \"$mount_state\" = mounted ]; then [ ! -L \"$root/.macluster-share-id\" ] && [ -f \"$root/.macluster-share-id\" ] && [ \"$(/bin/cat \"$root/.macluster-share-id\")\" = {} ] || {{ echo 'old share marker changed before detach' >&2; exit 1; }}; fi\n", shell_quote(marker)));
    }
    script.push_str("if [ \"$mount_state\" = mounted ]; then /sbin/umount \"$root\"; fi\n");
    script.push_str(&mount_check(None, root, &backup));
    script.push_str(path_checks());
    script.push_str("if [ ! -e \"$backup\" ] && [ -d \"$root\" ]; then\n  entries=$(/bin/ls -A \"$root\") || exit 1\n  if [ -n \"$entries\" ]; then\n    if [ ! -e \"$proof\" ]; then (umask 077; set -C; printf '%s\\n' \"$expected_proof\" > \"$proof\") || exit 1; fi\n    /bin/mv \"$root\" \"$backup\"\n  fi\nfi\n/bin/mkdir -p \"$root\"\nentries=$(/bin/ls -A \"$root\") || exit 1\n[ -z \"$entries\" ] || { echo 'primary target occupied; preserved data left untouched' >&2; exit 1; }\nif [ -d \"$backup\" ]; then printf 'Preserved previous primary directory: %s\\n' \"$backup\"; fi\n");
    script
}

pub(super) fn plan(
    node: &NodeConfig,
    storage: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
    namespace: &str,
    operation_id: &str,
) -> Result<PrimaryReusePlan, String> {
    Id128::parse(namespace)
        .map_err(|_| "invalid namespace UUID for primary preservation".to_owned())?;
    if !mount_root.is_absolute()
        || mount_root == Path::new("/")
        || mount_root.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || mount_root
            .to_string_lossy()
            .chars()
            .any(|c| c.is_whitespace())
    {
        return Err(
            "primary preservation requires an absolute directory without whitespace or traversal"
                .into(),
        );
    }
    let backup = backup_path(mount_root, namespace);
    let table = ssh_output(node, "/sbin/mount", None).map_err(|(_, e)| e)?;
    if !table.status.success() {
        return Err(command_error("cannot inspect old primary mounts", &table));
    }
    let old_source = old_mount(&String::from_utf8_lossy(&table.stdout), mount_root, &backup)?;
    let mut inspection = String::from("set -eu\n");
    inspection.push_str(&variables(mount_root, namespace));
    inspection.push_str(path_checks());
    inspection.push_str("if [ -e \"$root\" ]; then /usr/bin/stat -f '%d:%i' \"$root\"; else printf 'absent\\n'; fi\nif [ -L \"$root/.macluster-share-id\" ]; then echo 'share marker is a symlink' >&2; exit 1; fi\nif [ -f \"$root/.macluster-share-id\" ]; then /bin/cat \"$root/.macluster-share-id\"; else printf '\\n'; fi\n");
    let output = ssh_output(node, &inspection, None).map_err(|(_, e)| e)?;
    if !output.status.success() {
        return Err(command_error(
            "cannot safely inspect primary directory",
            &output,
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let (fingerprint, marker) = text
        .split_once('\n')
        .ok_or("malformed primary directory inspection")?;
    let marker = marker.trim();
    let marker = if marker.is_empty() {
        None
    } else {
        Id128::parse(marker).map_err(|_| "old primary directory has an invalid share UUID")?;
        Some(marker)
    };
    if old_source.is_some() && marker.is_none() {
        return Err(
            "old NFS mount has no valid macluster share marker; it was left untouched".into(),
        );
    }
    let (original, pending) = read_nfs_exports_update_baseline(node).map_err(|(_, e)| e)?;
    if pending {
        return Err(
            "a pending NFS exports transaction must be resolved before primary reuse".into(),
        );
    }
    let candidate = retire_exports(&original, mount_root, marker)?;
    let exports = if candidate == original {
        String::new()
    } else {
        nfs_exports_update_commands(&candidate, &original, operation_id)?
    };
    let preparation = preparation_script(
        mount_root,
        namespace,
        old_source.as_deref(),
        marker,
        fingerprint,
        &exports,
    );
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(
            "rerun mnode --add in Terminal to confirm preserving the previous primary directory"
                .into(),
        );
    }
    eprintln!(
        "Reuse primary path {} on {}. Any previous local contents will be preserved at {} and restored on removal/reset.{}",
        mount_root.display(),
        node.host,
        backup.display(),
        if old_source.is_some() {
            " The verified old NFS mount will be detached without force."
        } else {
            ""
        }
    );
    eprint!("Continue? [y/N] ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    if !shutdown_confirmation_accepted(&answer) {
        return Err("primary reuse cancelled; no primary directory or exports were changed".into());
    }
    Ok(PrimaryReusePlan {
        request: ClientMountRequest {
            source: nfs_mount_source(storage, source_root),
            mount_root: mount_root.to_owned(),
            source_alias: None,
            needs_mount: true,
            needs_privileged_mkdir: true,
            allow_existing_contents: false,
        },
        preparation,
        backup_path: backup,
    })
}

/// Read-only, unprivileged existence check. Any partial or suspicious artifact
/// also schedules privileged validation, rather than silently abandoning data.
pub(super) fn presence_probe(mount_root: &Path, namespace: &str) -> String {
    if Id128::parse(namespace).is_err() {
        return "exit 1\n".into();
    }
    let mut script = variables(mount_root, namespace);
    script.push_str(
        "[ -e \"$backup\" ] || [ -L \"$backup\" ] || [ -e \"$proof\" ] || [ -L \"$proof\" ]\n",
    );
    script
}

pub(super) fn restore_script(mount_root: &Path, namespace: &str) -> String {
    if Id128::parse(namespace).is_err() {
        return "echo 'invalid primary preservation namespace' >&2; exit 1\n".into();
    }
    let backup = backup_path(mount_root, namespace);
    let mut script = variables(mount_root, namespace);
    script.push_str(path_checks());
    script.push_str(&format!("if [ -e \"$proof\" ]; then printf '%s\\n' {} | /usr/bin/cmp - \"$proof\" >/dev/null 2>&1 || {{ echo 'primary preservation proof mismatch' >&2; exit 1; }}; fi\n", shell_quote(proof_text(mount_root, namespace).trim_end())));
    script.push_str("if [ -e \"$backup\" ]; then\n");
    script.push_str(&mount_check(None, mount_root, &backup));
    script.push_str("if [ -e \"$root\" ]; then entries=$(/bin/ls -A \"$root\") || exit 1; [ -z \"$entries\" ] || { echo 'primary target occupied; preserved directory left untouched' >&2; exit 1; }; /bin/rmdir \"$root\" || exit 1; fi\n/bin/mv \"$backup\" \"$root\" || exit 1\n/bin/rm \"$proof\" || exit 1\nprintf 'Restored previous primary directory: %s\\n' \"$root\"\nfi\n");
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const OLD: &str = "11112233-4455-6677-8899-aabbccddeeff";

    struct Fixture {
        dir: PathBuf,
        root: PathBuf,
        mounts: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("macluster-primary-reuse-{}", Id128::random()));
            fs::create_dir(&dir).unwrap();
            let dir = fs::canonicalize(dir).unwrap();
            let root = dir.join("primary");
            fs::create_dir(&root).unwrap();
            let mounts = dir.join("mount-table");
            fs::write(&mounts, "").unwrap();
            Self { dir, root, mounts }
        }
        fn run(&self, script: &str) -> Output {
            let script = script
                .replace(
                    "/sbin/mount",
                    &format!("/bin/cat {}", shell_quote(&self.mounts.to_string_lossy())),
                )
                .replace("/sbin/umount", "false")
                .replace(
                    "= '0:600'",
                    &format!("= '{}:600'", fs::metadata(&self.dir).unwrap().uid()),
                );
            Command::new("/bin/sh")
                .arg("-eu")
                .arg("-c")
                .arg(script)
                .output()
                .unwrap()
        }
        fn prepare(&self) -> String {
            let meta = fs::metadata(&self.root).unwrap();
            preparation_script(
                &self.root,
                UUID,
                None,
                None,
                &format!("{}:{}", meta.dev(), meta.ino()),
                "",
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn reuse_rejects_foreign_duplicate_and_nested_mounts() {
        let root = Path::new("/Users/Shared/macluster");
        let backup = backup_path(root, UUID);
        for table in [
            "/dev/disk1 on /Users/Shared/macluster (apfs, local)\n",
            "host:/old on /Users/Shared/macluster (nfs)\nhost:/other on /Users/Shared/macluster (nfs)\n",
            "host:/old on /Users/Shared/macluster/child (nfs)\n",
        ] {
            assert!(old_mount(table, root, &backup).is_err());
        }
        assert_eq!(
            old_mount(
                "host:/old on /Users/Shared/macluster (nfs, nodev)\n",
                root,
                &backup
            )
            .unwrap()
            .as_deref(),
            Some("host:/old")
        );
    }

    #[test]
    fn retirement_accepts_only_exact_owned_pairs() {
        let root = Path::new("/Users/Shared/macluster");
        let managed = format!(
            "# unrelated\n# macluster-managed {OLD} node1\n{} 10.0.0.2\n/other 10.0.0.3\n",
            root.display()
        );
        assert_eq!(
            retire_exports(&managed, root, Some(OLD)).unwrap(),
            "# unrelated\n/other 10.0.0.3\n"
        );
        assert!(retire_exports(&managed, root, Some(UUID)).is_err());
        for entry in [
            "/Users/Shared/macluster -alldirs 10.0.0.2",
            "/Users/Shared 10.0.0.2",
            "/Users/Shared/macluster/child 10.0.0.2",
        ] {
            assert!(retire_exports(&format!("{entry}\n"), root, Some(OLD)).is_err());
        }
        assert_eq!(
            retire_exports("# nothing\n", root, None).unwrap(),
            "# nothing\n"
        );
    }

    #[test]
    fn preparation_preserves_data_retries_and_restores() {
        let f = Fixture::new();
        fs::write(f.root.join("valuable"), "keep every byte").unwrap();
        let prepare = f.prepare();
        let first = f.run(&prepare);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let backup = backup_path(&f.root, UUID);
        assert_eq!(
            fs::read_to_string(backup.join("valuable")).unwrap(),
            "keep every byte"
        );
        assert!(f.run(&prepare).status.success());
        let restore = restore_script(&f.root, UUID);
        let output = f.run(&restore);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(f.root.join("valuable")).unwrap(),
            "keep every byte"
        );
        assert!(!backup.exists());
        assert!(!PathBuf::from(format!("{}.owner", backup.display())).exists());
        assert!(f.run(&restore).status.success());
    }

    #[test]
    fn mismatched_proof_or_occupied_target_keeps_all_data() {
        let f = Fixture::new();
        fs::write(f.root.join("valuable"), "original").unwrap();
        assert!(f.run(&f.prepare()).status.success());
        let backup = backup_path(&f.root, UUID);
        fs::write(f.root.join("new-file"), "new data").unwrap();
        assert!(!f.run(&restore_script(&f.root, UUID)).status.success());
        assert_eq!(
            fs::read_to_string(backup.join("valuable")).unwrap(),
            "original"
        );
        assert_eq!(
            fs::read_to_string(f.root.join("new-file")).unwrap(),
            "new data"
        );
        fs::remove_file(f.root.join("new-file")).unwrap();
        let proof = PathBuf::from(format!("{}.owner", backup.display()));
        fs::write(&proof, proof_text(&f.root, OLD)).unwrap();
        assert!(!f.run(&restore_script(&f.root, UUID)).status.success());
        assert!(backup.join("valuable").exists());
    }

    #[test]
    fn occupied_backup_without_proof_is_never_adopted() {
        let f = Fixture::new();
        let backup = backup_path(&f.root, UUID);
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("foreign"), "operator data").unwrap();
        assert!(!f.run(&f.prepare()).status.success());
        assert_eq!(
            fs::read_to_string(backup.join("foreign")).unwrap(),
            "operator data"
        );
    }
    #[test]
    fn interrupted_proof_creation_can_resume_without_adopting_foreign_mount() {
        let f = Fixture::new();
        fs::write(f.root.join("valuable"), "original").unwrap();
        let backup = backup_path(&f.root, UUID);
        let proof = PathBuf::from(format!("{}.owner", backup.display()));
        fs::write(&proof, proof_text(&f.root, UUID)).unwrap();
        fs::set_permissions(&proof, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &f.mounts,
            format!("foreign:/data on {} (nfs)\n", f.root.display()),
        )
        .unwrap();
        let prepare = f.prepare();
        assert!(!f.run(&prepare).status.success());
        assert!(f.root.join("valuable").exists());
        fs::write(&f.mounts, "").unwrap();
        assert!(f.run(&prepare).status.success());
        assert_eq!(
            fs::read_to_string(backup.join("valuable")).unwrap(),
            "original"
        );
    }
}
