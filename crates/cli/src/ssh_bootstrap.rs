use std::{
    env, fs,
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use macluster_core::config::NodeConfig;
use macluster_protocol::framing::sha256_hex;

use crate::node_admin;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshFailureKind {
    Authentication,
    UnknownHostKey,
    ChangedHostKey,
    Other,
}

struct SshIdentity {
    private_key: PathBuf,
    public_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostKeyDecision {
    Accept,
    Reject,
    Invalid,
}

struct ScannedHostKey {
    known_hosts_line: String,
    fingerprint: String,
    key_type: String,
}

fn classify_ssh_error(error: &str) -> SshFailureKind {
    let lower = error.to_ascii_lowercase();
    if lower.contains("no ") && lower.contains("host key is known") {
        SshFailureKind::UnknownHostKey
    } else if lower.contains("remote host identification has changed")
        || lower.contains("offending ") && lower.contains("host key")
    {
        SshFailureKind::ChangedHostKey
    } else if lower.contains("permission denied")
        || lower.contains("no supported authentication methods available")
    {
        SshFailureKind::Authentication
    } else {
        SshFailureKind::Other
    }
}

fn ssh_identity_path(home: &Path, endpoint: &str) -> Result<PathBuf, String> {
    if !home.is_absolute() {
        return Err("login account HOME must be an absolute path to create an SSH identity".into());
    }
    let digest = sha256_hex(endpoint.as_bytes()).map_err(|error| error.to_string())?;
    Ok(home
        .join(".ssh/macluster")
        .join(format!("node-{}", &digest[..20])))
}

pub(super) fn existing_ssh_identity_file(
    home: &Path,
    endpoint: &str,
) -> Result<Option<PathBuf>, String> {
    let private_key = ssh_identity_path(home, endpoint)?;
    let directory = private_key
        .parent()
        .ok_or_else(|| "SSH identity path has no parent directory".to_owned())?;
    for path in [home.join(".ssh"), directory.to_path_buf()] {
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o022 == 0 => {}
            Ok(_) => {
                return Err(format!(
                    "SSH directory {} is not a private directory owned by the current account",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect SSH directory {}: {error}",
                    path.display()
                ));
            }
        }
    }
    match fs::symlink_metadata(&private_key) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            Ok(Some(private_key))
        }
        Ok(_) => Err(format!(
            "SSH identity {} is not a private regular file owned by the current account",
            private_key.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot inspect SSH identity {}: {error}",
            private_key.display()
        )),
    }
}

fn ensure_local_keypair(home: &Path, endpoint: &str) -> Result<SshIdentity, String> {
    fs::create_dir_all(home)
        .map_err(|error| format!("cannot access login home {}: {error}", home.display()))?;
    let ssh_dir = home.join(".ssh");
    ensure_directory(&ssh_dir, 0o700, false)?;
    let key_dir = ssh_dir.join("macluster");
    ensure_directory(&key_dir, 0o700, true)?;

    let private_key = ssh_identity_path(home, endpoint)?;
    let public_path = PathBuf::from(format!("{}.pub", private_key.display()));
    let private_exists = path_exists_without_following_links(&private_key)?;
    let public_exists = path_exists_without_following_links(&public_path)?;
    if private_exists != public_exists {
        return Err(format!(
            "SSH identity {} is incomplete; refusing to overwrite it",
            private_key.display()
        ));
    }
    if !private_exists {
        let comment = sha256_hex(endpoint.as_bytes())
            .map_err(|error| error.to_string())?
            .chars()
            .take(12)
            .collect::<String>();
        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-C")
            .arg(format!("macluster-{comment}"))
            .arg("-f")
            .arg(&private_key)
            .output()
            .map_err(|error| format!("could not start ssh-keygen: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "could not create dedicated SSH identity {}: {}",
                private_key.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }

    let private_metadata = fs::symlink_metadata(&private_key).map_err(|error| {
        format!(
            "cannot inspect SSH identity {}: {error}",
            private_key.display()
        )
    })?;
    if !private_metadata.is_file() || private_metadata.file_type().is_symlink() {
        return Err(format!(
            "SSH identity {} is not a regular file",
            private_key.display()
        ));
    }
    if private_metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!(
            "SSH identity {} is not owned by the current account",
            private_key.display()
        ));
    }
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600)).map_err(|error| {
        format!(
            "cannot secure SSH identity {}: {error}",
            private_key.display()
        )
    })?;
    let public_key = read_ed25519_public_key(&public_path)?;
    let derived = Command::new("/usr/bin/ssh-keygen")
        .args(["-y", "-P", ""])
        .arg("-f")
        .arg(&private_key)
        .output()
        .map_err(|error| format!("could not verify SSH identity: {error}"))?;
    if !derived.status.success()
        || key_material(String::from_utf8_lossy(&derived.stdout).trim())
            != key_material(&public_key)
    {
        return Err(format!(
            "SSH identity {} is encrypted, invalid, or does not match its public key; refusing to replace it",
            private_key.display()
        ));
    }
    Ok(SshIdentity {
        private_key,
        public_key,
    })
}

fn ensure_directory(path: &Path, mode: u32, force_mode: bool) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "SSH directory {} must be a real directory, not a symlink or file",
                    path.display()
                ));
            }
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(format!(
                    "SSH directory {} is not owned by the current account",
                    path.display()
                ));
            }
            if force_mode {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
                    format!("cannot secure SSH directory {}: {error}", path.display())
                })?;
            } else if metadata.permissions().mode() & 0o022 != 0 {
                return Err(format!(
                    "SSH directory {} is writable by another account",
                    path.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|error| {
                format!("cannot create SSH directory {}: {error}", path.display())
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
                format!("cannot secure SSH directory {}: {error}", path.display())
            })?;
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect SSH directory {}: {error}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn path_exists_without_following_links(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "SSH identity path {} exists but is not a regular file; refusing to overwrite it",
            path.display()
        )),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "cannot inspect SSH identity {}: {error}",
            path.display()
        )),
    }
}

fn read_ed25519_public_key(path: &Path) -> Result<String, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read SSH public key {}: {error}", path.display()))?;
    let public_key = contents.trim();
    let fields: Vec<_> = public_key.split_whitespace().collect();
    if fields.len() < 2
        || fields[0] != "ssh-ed25519"
        || public_key.lines().count() != 1
        || public_key.chars().any(char::is_control)
    {
        return Err(format!(
            "{} is not a single Ed25519 public key",
            path.display()
        ));
    }
    Ok(public_key.to_owned())
}

fn key_material(key: &str) -> Option<(&str, &str)> {
    let mut fields = key.split_whitespace();
    Some((fields.next()?, fields.next()?))
}

fn install_public_key_script(public_key: &str) -> Result<String, String> {
    let fields: Vec<_> = public_key.split_whitespace().collect();
    if fields.len() < 2
        || fields[0] != "ssh-ed25519"
        || public_key.contains('\n')
        || public_key.chars().any(char::is_control)
    {
        return Err("refusing to install an invalid Ed25519 public key".into());
    }
    let key_blob = shell_quote(fields[1]);
    let public_key = shell_quote(public_key);
    Ok(format!(
        r#"set -eu
if [ -L "$HOME/.ssh" ]; then echo 'remote ~/.ssh is a symlink; refusing to edit it' >&2; exit 1; fi
if [ -e "$HOME/.ssh" ] && [ ! -d "$HOME/.ssh" ]; then echo 'remote ~/.ssh is not a directory' >&2; exit 1; fi
/bin/mkdir -p "$HOME/.ssh"
/bin/chmod 700 "$HOME/.ssh"
authorized_keys="$HOME/.ssh/authorized_keys"
if [ -L "$authorized_keys" ]; then echo 'remote authorized_keys is a symlink; refusing to edit it' >&2; exit 1; fi
if [ -e "$authorized_keys" ] && [ ! -f "$authorized_keys" ]; then echo 'remote authorized_keys is not a regular file' >&2; exit 1; fi
/usr/bin/touch "$authorized_keys"
/bin/chmod 600 "$authorized_keys"
key={public_key}
key_blob={key_blob}
if ! /usr/bin/grep -F -q "$key_blob" "$authorized_keys"; then
    if [ -s "$authorized_keys" ]; then
        last_byte=$(/usr/bin/tail -c 1 "$authorized_keys")
        if [ -n "$last_byte" ]; then printf '\n' >> "$authorized_keys"; fi
    fi
    printf '%s\n' "$key" >> "$authorized_keys"
fi
/bin/chmod 600 "$authorized_keys"
"#
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn host_key_decision(input: &str, fingerprint: &str) -> HostKeyDecision {
    let input = input.trim();
    match input.to_ascii_lowercase().as_str() {
        "y" | "yes" => HostKeyDecision::Accept,
        "" | "n" | "no" => HostKeyDecision::Reject,
        _ if input == fingerprint => HostKeyDecision::Accept,
        _ => HostKeyDecision::Invalid,
    }
}

fn offending_host_key_file(error: &str) -> Option<PathBuf> {
    error.lines().find_map(|line| {
        let line = line.trim();
        if !line.to_ascii_lowercase().starts_with("offending ") {
            return None;
        }
        let (_, location) = line.split_once(" in ")?;
        let (path, line_number) = location.rsplit_once(':')?;
        line_number.parse::<u64>().ok()?;
        Some(PathBuf::from(path))
    })
}

fn known_host_lookup(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

fn validate_known_hosts_file(path: &Path, home: &Path) -> Result<(), String> {
    let ssh_dir = home.join(".ssh");
    let ssh_metadata = fs::symlink_metadata(&ssh_dir).map_err(|error| {
        format!(
            "cannot inspect SSH directory {}: {error}",
            ssh_dir.display()
        )
    })?;
    if !ssh_metadata.is_dir()
        || ssh_metadata.file_type().is_symlink()
        || ssh_metadata.uid() != unsafe { libc::geteuid() }
        || ssh_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing to edit SSH trust: {} is not a private directory owned by the current account",
            ssh_dir.display()
        ));
    }

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect offending SSH trust file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing to edit unsafe SSH trust file {}",
            path.display()
        ));
    }
    if path.file_name().and_then(|name| name.to_str()) != Some("known_hosts")
        || path.parent().and_then(|parent| parent.canonicalize().ok())
            != ssh_dir.canonicalize().ok()
    {
        return Err(format!(
            "the changed key is recorded outside the default user known_hosts file: {}; no file was changed",
            path.display()
        ));
    }
    Ok(())
}

fn fingerprint_for_host_key(known_hosts_line: &str) -> Result<String, String> {
    let path = env::temp_dir().join(format!(
        "macluster-host-key-{}-{}",
        std::process::id(),
        macluster_protocol::identifiers::Id128::random()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("could not create temporary host-key file: {error}"))?;
        writeln!(file, "{known_hosts_line}")
            .map_err(|error| format!("could not write temporary host-key file: {error}"))?;
        drop(file);

        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-lf"])
            .arg(&path)
            .output()
            .map_err(|error| format!("could not calculate SSH host fingerprint: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "could not calculate SSH host fingerprint: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let fingerprint = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .nth(1)
            .filter(|value| value.starts_with("SHA256:"))
            .ok_or_else(|| "ssh-keygen returned an invalid host fingerprint".to_owned())?
            .to_owned();
        Ok(fingerprint)
    })();
    let _ = fs::remove_file(path);
    result
}

fn parse_host_key_scan_output(
    output: &str,
    host: &str,
    port: u16,
) -> Result<ScannedHostKey, String> {
    let lookup = known_host_lookup(host, port);
    let scan_port_alias = format!("[{host}]:{port}");
    let mut candidates = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with('#') {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || (fields[0] != lookup && fields[0] != scan_port_alias) {
            continue;
        }
        let priority = match fields[1] {
            "ssh-ed25519" => 0,
            "ecdsa-sha2-nistp256" => 1,
            "ecdsa-sha2-nistp384" => 2,
            "ecdsa-sha2-nistp521" => 3,
            "ssh-rsa" => 4,
            _ => continue,
        };
        let key_type = fields[1].to_owned();
        let known_hosts_line = format!("{lookup} {} {}", fields[1], fields[2]);
        candidates.push((priority, known_hosts_line, key_type));
    }
    candidates.sort_by_key(|candidate| candidate.0);
    let (_, known_hosts_line, key_type) = candidates.into_iter().next().ok_or_else(|| {
        format!(
            "could not scan an SSH host key for {lookup}; check that the node is reachable and offers an Ed25519, ECDSA, or RSA host key"
        )
    })?;
    let fingerprint = fingerprint_for_host_key(&known_hosts_line)?;
    Ok(ScannedHostKey {
        known_hosts_line,
        fingerprint,
        key_type,
    })
}

fn scan_host_key(node: &NodeConfig) -> Result<ScannedHostKey, String> {
    let port = node.ssh_port.unwrap_or(22);
    let output = Command::new("/usr/bin/ssh-keyscan")
        .args(["-T", "5", "-p"])
        .arg(port.to_string())
        .args(["-t", "ed25519,ecdsa,rsa"])
        .arg(&node.host)
        .output()
        .map_err(|error| format!("could not start ssh-keyscan for {}: {error}", node.host))?;
    parse_host_key_scan_output(&String::from_utf8_lossy(&output.stdout), &node.host, port).map_err(
        |error| {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if detail.is_empty() {
                error
            } else {
                format!("{error}: {detail}")
            }
        },
    )
}

fn prompt_for_host_key(node: &NodeConfig, key: &ScannedHostKey) -> Result<bool, String> {
    let account = node.ssh_user.as_deref().unwrap_or("current account");
    eprintln!(
        "SSH host fingerprint for {account}@{} ({}): {}",
        node.host, key.key_type, key.fingerprint
    );
    eprintln!(
        "Compare it with the fingerprint shown on the Mac itself or obtained through another trusted channel before accepting."
    );
    loop {
        eprint!("Trust this fingerprint? [y/N] (or paste the full fingerprint): ");
        io::stderr()
            .flush()
            .map_err(|error| format!("could not display host-key confirmation: {error}"))?;
        let mut response = String::new();
        let count = io::stdin()
            .read_line(&mut response)
            .map_err(|error| format!("could not read host-key confirmation: {error}"))?;
        if count == 0 {
            return Ok(false);
        }
        match host_key_decision(&response, &key.fingerprint) {
            HostKeyDecision::Accept => return Ok(true),
            HostKeyDecision::Reject => return Ok(false),
            HostKeyDecision::Invalid => {
                eprintln!("Enter y, n, or the exact SHA256 fingerprint shown above.");
            }
        }
    }
}

fn ensure_default_known_hosts_file(home: &Path) -> Result<PathBuf, String> {
    let ssh_dir = home.join(".ssh");
    ensure_directory(&ssh_dir, 0o700, false)?;
    let path = ssh_dir.join("known_hosts");
    match fs::symlink_metadata(&path) {
        Ok(_) => validate_known_hosts_file(&path, home)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "could not create SSH trust file {}: {error}",
                        path.display()
                    ));
                }
            }
            validate_known_hosts_file(&path, home)?;
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect SSH trust file {}: {error}",
                path.display()
            ));
        }
    }
    Ok(path)
}

fn known_host_entry_exists(path: &Path, lookup: &str) -> Result<bool, String> {
    let output = Command::new("/usr/bin/ssh-keygen")
        .args(["-F", lookup, "-f"])
        .arg(path)
        .output()
        .map_err(|error| format!("could not inspect SSH known_hosts: {error}"))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!(
            "could not inspect SSH known_hosts: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

fn append_known_host_entry(path: &Path, entry: &str, home: &Path) -> Result<(), String> {
    validate_known_hosts_file(path, home)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("could not open SSH trust file {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect SSH trust file: {error}"))?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
        || !metadata.is_file()
    {
        return Err(format!(
            "refusing to modify unsafe SSH trust file {}",
            path.display()
        ));
    }
    if metadata.len() > 0 {
        file.seek(SeekFrom::End(-1))
            .map_err(|error| format!("could not inspect the end of SSH trust file: {error}"))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last)
            .map_err(|error| format!("could not inspect the end of SSH trust file: {error}"))?;
        if last[0] != b'\n' {
            file.write_all(b"\n")
                .map_err(|error| format!("could not update SSH trust file: {error}"))?;
        }
    }
    writeln!(file, "{entry}")
        .map_err(|error| format!("could not update SSH trust file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("could not save SSH trust file: {error}"))
}

fn remove_known_host_entry(path: &Path, lookup: &str, home: &Path) -> Result<(), String> {
    validate_known_hosts_file(path, home)?;
    let found = Command::new("/usr/bin/ssh-keygen")
        .args(["-F", lookup, "-f"])
        .arg(path)
        .output()
        .map_err(|error| format!("could not inspect SSH known_hosts: {error}"))?;
    if !found.status.success() {
        return Err(format!(
            "could not find the exact {lookup} entry in {}; no file was changed",
            path.display()
        ));
    }
    let removed = Command::new("/usr/bin/ssh-keygen")
        .args(["-R", lookup, "-f"])
        .arg(path)
        .output()
        .map_err(|error| format!("could not remove the stale SSH host key: {error}"))?;
    if !removed.status.success() {
        return Err(format!(
            "could not remove the exact {lookup} entry from {}: {}",
            path.display(),
            String::from_utf8_lossy(&removed.stderr).trim()
        ));
    }
    Ok(())
}

fn recover_changed_host_key(node: &NodeConfig, error: &str) -> Result<(), String> {
    if unsafe { libc::isatty(0) } != 1 {
        return Err(format!(
            "SSH host key for {} changed. Run mnode from an interactive Terminal to verify the replacement fingerprint; no known_hosts entry was changed",
            node.host
        ));
    }
    let path = offending_host_key_file(error).ok_or_else(|| {
        format!(
            "SSH host key for {} changed, but OpenSSH did not identify a removable offending entry; inspect known_hosts manually",
            node.host
        )
    })?;
    let home = env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        "cannot locate the login account's HOME for SSH host-key recovery".to_owned()
    })?;
    validate_known_hosts_file(&path, &home)?;
    let key = scan_host_key(node)?;
    if !prompt_for_host_key(node, &key)? {
        return Err(format!(
            "replacement SSH host key for {} was not accepted; known_hosts was left unchanged",
            node.host
        ));
    }
    let lookup = known_host_lookup(&node.host, node.ssh_port.unwrap_or(22));
    remove_known_host_entry(&path, &lookup, &home)?;
    append_known_host_entry(&path, &key.known_hosts_line, &home)?;
    eprintln!(
        "Replaced only the stale {lookup} entry in {}. The exact scanned key is now pinned; the next SSH connection will reject any different key.",
        path.display()
    );
    Ok(())
}

pub(super) fn ensure_ssh_access(node: &mut NodeConfig, endpoint: &str) -> Result<(), String> {
    match probe_key_auth(node) {
        Ok(()) => return Ok(()),
        Err(error) => match classify_ssh_error(&error) {
            SshFailureKind::Authentication => {}
            SshFailureKind::UnknownHostKey => {
                run_host_key_confirmation(node)?;
                match probe_key_auth(node) {
                    Ok(()) => return Ok(()),
                    Err(error) => match classify_ssh_error(&error) {
                        SshFailureKind::Authentication => {}
                        SshFailureKind::UnknownHostKey | SshFailureKind::ChangedHostKey => {
                            return Err(format!(
                                "SSH host key for {} was not accepted; verify its fingerprint and rerun mnode",
                                node.host
                            ));
                        }
                        SshFailureKind::Other => return Err(error),
                    },
                }
            }
            SshFailureKind::ChangedHostKey => {
                recover_changed_host_key(node, &error)?;
                match probe_key_auth(node) {
                    Ok(()) => return Ok(()),
                    Err(error) => match classify_ssh_error(&error) {
                        SshFailureKind::Authentication => {}
                        SshFailureKind::UnknownHostKey => {
                            return Err(format!(
                                "replacement SSH host key for {} was not accepted; rerun mnode and verify its fingerprint",
                                node.host
                            ));
                        }
                        SshFailureKind::ChangedHostKey => {
                            return Err(format!(
                                "SSH host key for {} changed again while being verified; stop and inspect the host identity",
                                node.host
                            ));
                        }
                        SshFailureKind::Other => return Err(error),
                    },
                }
            }
            SshFailureKind::Other => return Err(error),
        },
    }

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find the login account's HOME for SSH key setup".to_owned())?;
    let identity = ensure_local_keypair(&home, endpoint)?;
    let identity_text = identity
        .private_key
        .to_str()
        .ok_or_else(|| "generated SSH identity path is not valid UTF-8".to_owned())?
        .to_owned();
    node.ssh_identity_file = Some(identity_text);

    match probe_key_auth(node) {
        Ok(()) => return Ok(()),
        Err(error) if classify_ssh_error(&error) == SshFailureKind::Authentication => {}
        Err(error) => return Err(error),
    }
    let script = install_public_key_script(&identity.public_key)?;
    let account = node
        .ssh_user
        .as_deref()
        .unwrap_or("the configured SSH account");
    eprintln!(
        "SSH key login is not configured for {account}@{}. Enter that account's login password once to install macluster's SSH key. This is separate from any administrator password requested later.",
        node.host
    );
    if !run_interactive_ssh(
        node,
        &[
            "StrictHostKeyChecking=yes",
            "PreferredAuthentications=password",
            "PasswordAuthentication=yes",
            "KbdInteractiveAuthentication=no",
            "PubkeyAuthentication=no",
            "NumberOfPasswordPrompts=1",
        ],
        &script,
    )? {
        return Err(format!(
            "could not install the SSH public key on {}; check the account password and make sure macOS Remote Login allows password authentication",
            node.host
        ));
    }
    probe_key_auth(node).map_err(|error| {
        format!(
            "the public key was installed on {}, but noninteractive key verification failed: {error}",
            node.host
        )
    })
}

fn probe_key_auth(node: &NodeConfig) -> Result<(), String> {
    match node_admin::ssh_output(node, "/usr/bin/true", None) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!(
            "SSH key preflight failed for {}: {}",
            node.host,
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err((_, error)) => Err(error),
    }
}

fn run_host_key_confirmation(node: &NodeConfig) -> Result<(), String> {
    if unsafe { libc::isatty(0) } != 1 {
        return Err("SSH host-key confirmation requires an interactive Terminal".into());
    }
    let home = env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        "cannot locate the login account's HOME for SSH host-key confirmation".to_owned()
    })?;
    let key = scan_host_key(node)?;
    if !prompt_for_host_key(node, &key)? {
        return Err(format!(
            "SSH host key for {} was not accepted; no known_hosts entry was changed",
            node.host
        ));
    }
    let path = ensure_default_known_hosts_file(&home)?;
    let lookup = known_host_lookup(&node.host, node.ssh_port.unwrap_or(22));
    if known_host_entry_exists(&path, &lookup)? {
        return Err(format!(
            "SSH trust entry for {lookup} already exists in {}; OpenSSH reported it as unknown, so no entry was changed",
            path.display()
        ));
    }
    append_known_host_entry(&path, &key.known_hosts_line, &home)?;
    eprintln!(
        "Pinned the confirmed SSH host key for {lookup}; the next connection will verify that exact key."
    );
    Ok(())
}

fn run_interactive_ssh(
    node: &NodeConfig,
    options: &[&str],
    remote_command: &str,
) -> Result<bool, String> {
    if unsafe { libc::isatty(0) } != 1 {
        return Err("SSH password and host-key prompts require an interactive Terminal".into());
    }
    let mut command = Command::new("/usr/bin/ssh");
    command
        .arg("-T")
        .arg("-oLogLevel=ERROR")
        .arg("-oBatchMode=no")
        .arg("-oConnectTimeout=5")
        .arg("-oServerAliveInterval=5")
        .arg("-oServerAliveCountMax=1");
    for option in options {
        command.arg(format!("-o{option}"));
    }
    node.add_ssh_identity_args(&mut command);
    command
        .arg(&node.host)
        .arg(remote_command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
        .status()
        .map(|status| status.success())
        .map_err(|error| format!("could not start interactive SSH setup: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        HostKeyDecision, SshFailureKind, append_known_host_entry, classify_ssh_error,
        ensure_local_keypair, existing_ssh_identity_file, host_key_decision,
        install_public_key_script, known_host_lookup, offending_host_key_file,
        parse_host_key_scan_output, remove_known_host_entry, ssh_identity_path,
        validate_known_hosts_file,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
    };

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "macluster-ssh-bootstrap-{label}-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ))
    }

    #[test]
    fn identity_path_is_stable_and_unique_per_endpoint() {
        let home = Path::new("/Users/operator");
        let first = ssh_identity_path(home, "worker@192.0.2.10:22").unwrap();
        let retry = ssh_identity_path(home, "worker@192.0.2.10:22").unwrap();
        let other = ssh_identity_path(home, "worker@192.0.2.11:22").unwrap();

        assert_eq!(first, retry);
        assert_ne!(first, other);
        assert!(first.starts_with(home.join(".ssh/macluster")));
    }

    #[test]
    fn existing_identity_file_is_reused_only_when_private_and_owned() {
        let root = temp_root("existing-identity");
        let home = root.join("home");
        let endpoint = "worker@192.0.2.10:22";
        let key = ssh_identity_path(&home, endpoint).unwrap();
        fs::create_dir_all(key.parent().unwrap()).unwrap();
        fs::set_permissions(home.join(".ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            home.join(".ssh/macluster"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        assert_eq!(existing_ssh_identity_file(&home, endpoint).unwrap(), None);
        fs::write(&key, "private key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            existing_ssh_identity_file(&home, endpoint).unwrap(),
            Some(key.clone())
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            existing_ssh_identity_file(&home, endpoint)
                .unwrap_err()
                .contains("not a private regular file")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn generated_key_is_ed25519_unencrypted_and_private() {
        let root = temp_root("key");
        let home = root.join("home with spaces");

        let identity = ensure_local_keypair(&home, "worker@192.0.2.10:22").unwrap();
        let retry = ensure_local_keypair(&home, "worker@192.0.2.10:22").unwrap();

        assert_eq!(identity.private_key, retry.private_key);
        assert_eq!(identity.public_key, retry.public_key);
        assert!(identity.public_key.starts_with("ssh-ed25519 "));
        assert_eq!(
            fs::metadata(&identity.private_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(identity.private_key.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn public_key_install_script_preserves_existing_entries_and_avoids_duplicates() {
        let root = temp_root("authorized-keys");
        let home = root.join("remote-home");
        let existing_key = "ssh-ed25519 AAAAexisting operator@old";
        let new_key = "ssh-ed25519 AAAAnew macluster@worker";
        let script = install_public_key_script(new_key).unwrap();
        let authorized_keys = home.join(".ssh/authorized_keys");
        fs::create_dir_all(authorized_keys.parent().unwrap()).unwrap();
        fs::write(&authorized_keys, existing_key).unwrap();

        for _ in 0..2 {
            let output = Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .env("HOME", &home)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let contents = fs::read_to_string(&authorized_keys).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.lines().any(|line| line == existing_key));
        assert!(contents.lines().any(|line| line == new_key));
        assert_eq!(
            fs::metadata(authorized_keys.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&authorized_keys).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let contents = fs::read_to_string(&authorized_keys)
            .unwrap()
            .replace(new_key, "ssh-ed25519 AAAAnew preserved-comment");
        fs::write(&authorized_keys, contents).unwrap();
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&authorized_keys)
                .unwrap()
                .lines()
                .count(),
            2
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn public_key_install_script_refuses_non_file_authorized_keys() {
        let root = temp_root("authorized-keys-directory");
        let home = root.join("remote-home");
        let authorized_keys = home.join(".ssh/authorized_keys");
        fs::create_dir_all(&authorized_keys).unwrap();
        let script = install_public_key_script("ssh-ed25519 AAAAnew macluster@worker").unwrap();

        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular file"));
        assert!(authorized_keys.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ssh_error_classification_separates_password_auth_from_host_key_problems() {
        assert_eq!(
            classify_ssh_error("Permission denied (publickey,password)."),
            SshFailureKind::Authentication
        );
        assert_eq!(
            classify_ssh_error(
                "No ED25519 host key is known for 192.0.2.10 and you requested strict checking."
            ),
            SshFailureKind::UnknownHostKey
        );
        assert_eq!(
            classify_ssh_error("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"),
            SshFailureKind::ChangedHostKey
        );
        assert_eq!(
            classify_ssh_error("Connection timed out"),
            SshFailureKind::Other
        );
    }

    #[test]
    fn changed_host_key_error_extracts_the_offending_file_path() {
        let error = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nOffending ED25519 key in /Users/operator/.ssh with spaces/known_hosts:36\nHost key verification failed.";
        assert_eq!(
            offending_host_key_file(error).as_deref(),
            Some(Path::new("/Users/operator/.ssh with spaces/known_hosts"))
        );
        assert_eq!(
            offending_host_key_file("Host key verification failed."),
            None
        );
    }

    #[test]
    fn host_key_lookup_formats_nondefault_ports() {
        assert_eq!(known_host_lookup("192.0.2.3", 22), "192.0.2.3");
        assert_eq!(known_host_lookup("192.0.2.3", 2222), "[192.0.2.3]:2222");
    }

    #[test]
    fn host_key_confirmation_accepts_y_or_exact_fingerprint_and_defaults_to_no() {
        let fingerprint = "SHA256:AbCdEf0123456789";
        assert_eq!(host_key_decision("y", fingerprint), HostKeyDecision::Accept);
        assert_eq!(
            host_key_decision(" YES ", fingerprint),
            HostKeyDecision::Accept
        );
        assert_eq!(
            host_key_decision(fingerprint, fingerprint),
            HostKeyDecision::Accept
        );
        assert_eq!(host_key_decision("n", fingerprint), HostKeyDecision::Reject);
        assert_eq!(host_key_decision("", fingerprint), HostKeyDecision::Reject);
        assert_eq!(
            host_key_decision("SHA256:abcdef0123456789", fingerprint),
            HostKeyDecision::Invalid
        );
    }

    #[test]
    fn stale_host_key_removal_is_exact_and_preserves_a_backup() {
        let root = temp_root("replace-known-host");
        let home = root.join("home");
        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let key = ensure_local_keypair(&root.join("key-home"), "known-host-test").unwrap();
        let path = ssh_dir.join("known_hosts");
        let contents = format!(
            "192.0.2.3 {}\n192.0.2.4 {}\n",
            key.public_key, key.public_key
        );
        fs::write(&path, &contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        validate_known_hosts_file(&path, &home).unwrap();
        remove_known_host_entry(&path, "192.0.2.3", &home).unwrap();

        let remaining = fs::read_to_string(&path).unwrap();
        assert!(!remaining.contains("192.0.2.3"));
        assert!(remaining.contains("192.0.2.4"));
        let backup = PathBuf::from(format!("{}.old", path.display()));
        assert_eq!(fs::read_to_string(backup).unwrap(), contents);
        assert!(validate_known_hosts_file(&root.join("foreign/known_hosts"), &home).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scanned_host_key_prefers_ed25519_and_displays_its_fingerprint() {
        let root = temp_root("scan-host-key");
        let identity = ensure_local_keypair(&root.join("key-home"), "known-host-test").unwrap();
        let key = identity.public_key.split_whitespace().collect::<Vec<_>>();
        let output = format!(
            "# scan banner\n192.0.2.3 ecdsa-sha2-nistp256 aaaa\n192.0.2.3 {} {}\n",
            key[0], key[1]
        );

        let scanned = parse_host_key_scan_output(&output, "192.0.2.3", 22).unwrap();

        assert_eq!(scanned.key_type, "ssh-ed25519");
        assert_eq!(
            scanned.known_hosts_line,
            format!("192.0.2.3 {} {}", key[0], key[1])
        );
        assert!(scanned.fingerprint.starts_with("SHA256:"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scanned_host_key_normalizes_nondefault_port_and_hostkey_fingerprint_input() {
        let root = temp_root("scan-host-key-port");
        let identity = ensure_local_keypair(&root.join("key-home"), "known-host-test").unwrap();
        let output = format!("[192.0.2.3]:2222 {}\n", identity.public_key);

        let scanned = parse_host_key_scan_output(&output, "192.0.2.3", 2222).unwrap();

        assert!(
            scanned
                .known_hosts_line
                .starts_with("[192.0.2.3]:2222 ssh-ed25519 ")
        );
        assert_eq!(
            host_key_decision(&scanned.fingerprint, &scanned.fingerprint),
            HostKeyDecision::Accept
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn appending_a_confirmed_host_key_preserves_existing_file_contents() {
        let root = temp_root("append-known-host");
        let home = root.join("home");
        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = ssh_dir.join("known_hosts");
        fs::write(&path, "192.0.2.1 ssh-ed25519 AAAAold").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        append_known_host_entry(&path, "192.0.2.3 ssh-ed25519 AAAAnew", &home).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "192.0.2.1 ssh-ed25519 AAAAold\n192.0.2.3 ssh-ed25519 AAAAnew\n"
        );
        let _ = fs::remove_dir_all(root);
    }
}
