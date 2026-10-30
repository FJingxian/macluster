use super::*;
use std::{
    net::{SocketAddr, TcpStream},
    os::unix::fs::DirBuilderExt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const INVENTORY_FILE: &str = "node-addresses.json";
const MIGRATION_FILE: &str = "node-address-migration.json";
const PROPOSAL_FILE: &str = "node-address-proposal.json";
const CHECK_INTERVAL_MS: u64 = 30_000;
const SUBNET_SCAN_INTERVAL_MS: u64 = 5 * 60_000;
pub(super) const MAINTENANCE_OPERATION: &str = "node address and NFS migration";

fn full_subnet_scan_due(last_scan_ms: u64, now_ms: u64, force: bool) -> bool {
    force || last_scan_ms == 0 || now_ms.saturating_sub(last_scan_ms) >= SUBNET_SCAN_INTERVAL_MS
}

#[derive(Clone, Debug)]
struct InterfaceAddress {
    interface: String,
    address: Ipv4Addr,
    mask: u32,
    mac: Option<String>,
}

impl InterfaceAddress {
    fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(self.address) & self.mask == u32::from(address) & self.mask
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AddressRecord {
    machine_uuid: String,
    host: String,
    mac: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
struct Inventory {
    share_uuid: String,
    #[serde(default)]
    config_digest: String,
    checked_ms: u64,
    #[serde(default)]
    last_subnet_scan_ms: u64,
    nodes: BTreeMap<String, AddressRecord>,
}

#[derive(Deserialize, Serialize)]
struct Migration {
    operation_id: String,
    config_path: PathBuf,
    state_dir: PathBuf,
    old_source: String,
    candidate_source: String,
    phase: String,
    completed: BTreeSet<String>,
}

fn normalize_mac(value: &str) -> Option<String> {
    let bytes = value
        .split(':')
        .map(|part| {
            if part.is_empty() || part.len() > 2 {
                return None;
            }
            u8::from_str_radix(part, 16).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    if bytes.len() != 6 || bytes[0] & 1 != 0 || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn parse_interfaces(text: &str) -> Vec<InterfaceAddress> {
    let mut result = Vec::new();
    let mut interface = String::new();
    let mut mac = None;
    let mut up = false;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace)
            && let Some((name, flags)) = line.split_once(':')
        {
            interface = name.to_owned();
            mac = None;
            up = flags.contains("UP");
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"ether") {
            mac = fields.get(1).and_then(|value| normalize_mac(value));
        }
        if up && fields.first() == Some(&"inet") {
            let Some(address) = fields
                .get(1)
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            let Some(mask) = fields
                .windows(2)
                .find(|pair| pair[0] == "netmask")
                .and_then(|pair| u32::from_str_radix(pair[1].trim_start_matches("0x"), 16).ok())
            else {
                continue;
            };
            if address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || mask == 0
            {
                continue;
            }
            // A valid subnet mask consists of leading ones followed by zeroes.
            if (!mask)
                .checked_add(1)
                .is_none_or(|value| value & !mask != 0)
            {
                continue;
            }
            result.push(InterfaceAddress {
                interface: interface.clone(),
                address,
                mask,
                mac: mac.clone(),
            });
        }
    }
    result
}

fn parse_neighbors(text: &str) -> Vec<(Ipv4Addr, String)> {
    text.lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let address = fields.get(1)?.trim_matches(['(', ')']).parse().ok()?;
            if fields.get(2) != Some(&"at") {
                return None;
            }
            Some((address, normalize_mac(fields.get(3)?)?))
        })
        .collect()
}

fn matching_interface<'a>(
    old: Ipv4Addr,
    interfaces: &'a [InterfaceAddress],
    mac: Option<&str>,
) -> Option<&'a InterfaceAddress> {
    let candidates = interfaces
        .iter()
        .filter(|interface| interface.contains(old))
        .collect::<Vec<_>>();
    if let Some(mac) = mac {
        let matching = candidates
            .iter()
            .copied()
            .filter(|interface| interface.mac.as_deref() == Some(mac))
            .collect::<Vec<_>>();
        if matching.len() == 1 {
            return matching.first().copied();
        }
    }
    if candidates.len() == 1 {
        candidates.first().copied()
    } else {
        None
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn connection_cache_payload(registered: &str, current: &str, previous: Option<&[u8]>) -> String {
    let mut fields = vec![registered.to_owned(), current.to_owned()];
    if let Some(previous) = previous.and_then(|bytes| std::str::from_utf8(bytes).ok()) {
        for value in previous.split_whitespace() {
            if fields.len() >= 8 {
                break;
            }
            if value.parse::<Ipv4Addr>().is_ok() && !fields.iter().any(|field| field == value) {
                fields.push(value.to_owned());
            }
        }
    }
    fields.join(" ") + "\n"
}

fn read_private_json<T: serde::de::DeserializeOwned>(path: &Path) -> AppResult<Option<T>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 2 * 1024 * 1024
    {
        return Err((
            1,
            format!(
                "address recovery record {} is not a private regular file",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io_error)?;
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        (
            1,
            format!(
                "invalid address recovery record {}: {error}",
                path.display()
            ),
        )
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    atomic_write(
        path,
        &serde_json::to_vec(value).map_err(|error| (1, error.to_string()))?,
    )
}

fn remove_stale_proposal(path: &Path) -> AppResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn neighbors() -> Vec<(Ipv4Addr, String)> {
    Command::new("/usr/sbin/arp")
        .arg("-an")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_neighbors(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

fn local_interfaces() -> AppResult<Vec<InterfaceAddress>> {
    let output = Command::new("/sbin/ifconfig")
        .arg("-a")
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("cannot inspect cluster network interfaces", &output),
        ));
    }
    Ok(parse_interfaces(&String::from_utf8_lossy(&output.stdout)))
}

fn ensure_host_key_pin(node: &NodeConfig) -> AppResult<bool> {
    let Some((path, alias)) = node.ssh_host_key_pin() else {
        return Ok(false);
    };
    for directory in [path.parent().and_then(Path::parent), path.parent()]
        .into_iter()
        .flatten()
    {
        match fs::symlink_metadata(directory) {
            Ok(metadata)
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o022 == 0 => {}
            Ok(_) => {
                return Err((
                    1,
                    format!("unsafe SSH trust directory {}", directory.display()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err((1, format!("unsafe node host-key pin {}", path.display())));
        }
        return Ok(true);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| (1, "cannot locate SSH trust files".into()))?;
    let lookup = if node.ssh_port.unwrap_or(22) == 22 {
        node.host.clone()
    } else {
        format!("[{}]:{}", node.host, node.ssh_port.unwrap_or(22))
    };
    let mut keys = BTreeSet::new();
    for file in [
        home.join(".ssh/known_hosts"),
        PathBuf::from("/etc/ssh/ssh_known_hosts"),
    ] {
        if !file.is_file() {
            continue;
        }
        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-F", &lookup, "-f"])
            .arg(file)
            .output()
            .map_err(io_error)?;
        if !output.status.success() {
            continue;
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with('#') || line.starts_with('@') {
                continue;
            }
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 3
                && matches!(
                    fields[1],
                    "ssh-ed25519"
                        | "ecdsa-sha2-nistp256"
                        | "ecdsa-sha2-nistp384"
                        | "ecdsa-sha2-nistp521"
                        | "ssh-rsa"
                )
            {
                keys.insert(format!("{alias} {} {}\n", fields[1], fields[2]));
            }
        }
    }
    if keys.is_empty() {
        return Ok(false);
    }
    let directory = path.parent().expect("pin has parent");
    let mut builder = fs::DirBuilder::new();
    builder
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(io_error)?;
    let metadata = fs::symlink_metadata(directory).map_err(io_error)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err((1, "node SSH trust directory is not privately owned".into()));
    }
    let temporary = directory.join(format!(".node-host-key-{}", Id128::random()));
    let result = (|| -> AppResult<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(keys.into_iter().collect::<String>().as_bytes())
            .map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        match fs::hard_link(&temporary, &path) {
            Ok(()) => File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result?;
    Ok(true)
}

fn tcp_available(address: Ipv4Addr, port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from((address, port)),
        Duration::from_millis(180),
    )
    .is_ok()
}

fn verified_record(node: &NodeConfig, address: Ipv4Addr) -> AppResult<AddressRecord> {
    let expected = node.machine_uuid.as_deref().ok_or_else(|| {
        (
            1,
            "automatic node discovery requires a registered machine UUID".into(),
        )
    })?;
    let output = ssh_output(
        node,
        "/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice; /sbin/ifconfig -a",
        None,
    )?;
    if !output.status.success() {
        return Err((
            1,
            command_error("cannot inspect node network identity", &output),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let uuid = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| {
            line.rsplit_once('=')
                .map(|(_, value)| value.trim().trim_matches('"'))
        })
        .ok_or_else(|| (1, "candidate node did not return its platform UUID".into()))?;
    let actual = Id128::parse(uuid)
        .map_err(|error| (1, error.to_string()))?
        .to_string();
    validate_pending_node_identity("address discovery", Some(expected), &actual)
        .map_err(|error| (1, error))?;
    let interfaces = parse_interfaces(&text);
    let interface = interfaces
        .iter()
        .find(|interface| interface.address == address)
        .ok_or_else(|| {
            (
                1,
                "verified node does not advertise the candidate address".into(),
            )
        })?;
    Ok(AddressRecord {
        machine_uuid: actual,
        host: address.to_string(),
        mac: interface.mac.clone(),
    })
}

fn subnet_candidates(
    interface: &InterfaceAddress,
    local: &[InterfaceAddress],
    neighbors: &[(Ipv4Addr, String)],
    mac: Option<&str>,
) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let allowed = |address: Ipv4Addr| {
        interface.contains(address)
            && !local.iter().any(|entry| entry.address == address)
            && address != Ipv4Addr::from(u32::from(interface.address) & interface.mask)
            && address != Ipv4Addr::from(u32::from(interface.address) | !interface.mask)
    };
    let mut preferred = neighbors
        .iter()
        .filter(|(address, found)| allowed(*address) && mac == Some(found.as_str()))
        .map(|(address, _)| *address)
        .collect::<BTreeSet<_>>();
    if preferred.is_empty() {
        preferred.extend(
            neighbors
                .iter()
                .filter(|(address, _)| allowed(*address))
                .map(|(address, _)| *address),
        );
    }
    let mut rest = neighbors
        .iter()
        .filter(|(address, _)| allowed(*address) && !preferred.contains(address))
        .map(|(address, _)| *address)
        .collect::<BTreeSet<_>>();
    let hosts = u64::from(!interface.mask) + 1;
    if hosts <= 1024 {
        let base = u32::from(interface.address) & interface.mask;
        for offset in 1..hosts.saturating_sub(1) {
            let address = Ipv4Addr::from(base + offset as u32);
            if allowed(address) && !preferred.contains(&address) {
                rest.insert(address);
            }
        }
    }
    (preferred.into_iter().collect(), rest.into_iter().collect())
}

fn scan_candidates(
    node: &NodeConfig,
    candidates: &[Ipv4Addr],
) -> AppResult<Option<(NodeConfig, AddressRecord)>> {
    let next = AtomicUsize::new(0);
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut matches = thread::scope(|scope| {
        let handles = (0..8.min(candidates.len()))
            .map(|_| {
                let next = &next;
                scope.spawn(move || {
                    let mut matches = Vec::new();
                    while Instant::now() < deadline {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(address) = candidates.get(index).copied() else {
                            break;
                        };
                        if !tcp_available(address, node.ssh_port.unwrap_or(22)) {
                            continue;
                        }
                        let mut candidate = node.clone();
                        candidate.host = address.to_string();
                        if let Ok(record) = verified_record(&candidate, address) {
                            matches.push((candidate, record));
                        }
                    }
                    matches
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .flatten()
            .collect::<Vec<_>>()
    });
    if matches.len() > 1 {
        return Err((1, "multiple addresses report the registered node identity; automatic migration was refused".into()));
    }
    Ok(matches.pop())
}

fn discover_remote(
    node: &NodeConfig,
    record: Option<&AddressRecord>,
    interfaces: &[InterfaceAddress],
    force: bool,
    allow_full_subnet_scan: bool,
) -> AppResult<(Option<(NodeConfig, AddressRecord)>, bool)> {
    let Ok(old_address) = node.host.parse::<Ipv4Addr>() else {
        return Ok((None, false));
    };
    let Some(interface) = matching_interface(old_address, interfaces, None) else {
        return Ok((None, false));
    };
    let pinned = ensure_host_key_pin(node)?;
    let local = interfaces.iter().any(|entry| entry.address == old_address);
    let reachable = !local && tcp_available(old_address, node.ssh_port.unwrap_or(22));
    let arp = neighbors();
    let mac_matches = record
        .and_then(|record| record.mac.as_deref())
        .is_some_and(|mac| {
            arp.iter()
                .any(|(ip, found)| *ip == old_address && found == mac)
        });
    if reachable {
        if !force
            && mac_matches
            && let Some(record) = record
        {
            return Ok((Some((node.clone(), record.clone())), false));
        }
        if let Ok(record) = verified_record(node, old_address) {
            return Ok((Some((node.clone(), record)), false));
        }
    }
    // A MAC address narrows the search. Only a trusted host key and matching
    // machine UUID authorize a replacement address; never trust ssh-keyscan.
    if !pinned {
        return Ok((None, false));
    }
    eprintln!(
        "Searching {} for the registered node formerly at {} (MAC + trusted SSH key + machine UUID)",
        interface.interface, node.host
    );
    let (preferred, rest) = subnet_candidates(
        interface,
        interfaces,
        &arp,
        record.and_then(|entry| entry.mac.as_deref()),
    );
    if let Some(found) = scan_candidates(node, &preferred)? {
        return Ok((Some(found), false));
    }
    if !allow_full_subnet_scan {
        return Ok((None, false));
    }
    Ok((scan_candidates(node, &rest)?, true))
}

fn address_candidate(
    source: &str,
    config: &ClusterConfig,
    replacements: &BTreeMap<String, String>,
) -> AppResult<String> {
    let mut candidate = source.to_owned();
    for (node_id, address) in replacements {
        if !config.nodes.contains_key(node_id) || address.parse::<Ipv4Addr>().is_err() {
            return Err((2, "invalid node address replacement".into()));
        }
        candidate = replace_node_string_key(&candidate, node_id, "host", address)?;
    }
    // Validate after replacing all hosts: simultaneous address swaps can have
    // duplicate intermediate hosts, but the committed configuration cannot.
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

fn migrated_exports(
    original: &str,
    old: &[NfsExportRequest],
    new: &[NfsExportRequest],
) -> Result<String, String> {
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    for request in old {
        let replacement = new
            .iter()
            .find(|next| next.share_uuid == request.share_uuid && next.node_id == request.node_id)
            .ok_or_else(|| "address migration changed NFS share identity".to_owned())?;
        let marker = format!(
            "# macluster-managed {} {}",
            request.share_uuid, request.node_id
        );
        let positions = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| **line == marker)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if positions.len() > 1 {
            return Err("duplicate managed NFS marker during address migration".into());
        }
        if let Some(index) = positions.first().copied() {
            let old_rule = format!("{} {}", request.root, request.client_ip);
            let new_rule = format!("{} {}", replacement.root, replacement.client_ip);
            let current = lines
                .get_mut(index + 1)
                .ok_or_else(|| "managed NFS export has no rule".to_owned())?;
            if current != &old_rule && current != &new_rule {
                return Err(
                    "managed NFS export changed outside address migration; refusing overwrite"
                        .into(),
                );
            }
            *current = new_rule;
        }
    }
    let candidate = if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    };
    plan_ensure_nfs_exports(&candidate, new).map(|(candidate, _, _)| candidate)
}

fn export_groups(config: &ClusterConfig) -> BTreeMap<String, Vec<NfsExportRequest>> {
    let mut entries = Vec::new();
    for (node_id, node) in &config.nodes {
        for (server_id, requests) in
            pending_managed_export_cleanup_plan(config, node_id, &node.host)
        {
            entries.extend(
                requests
                    .into_iter()
                    .map(|(_, request)| (server_id.clone(), request)),
            );
        }
    }
    group_nfs_export_requests(entries)
}

fn checked_migration(
    config_path: &Path,
    state_dir: &Path,
    migration: &Migration,
) -> AppResult<(ClusterConfig, ClusterConfig)> {
    if config_path.canonicalize().map_err(io_error)? != migration.config_path
        || state_dir.canonicalize().map_err(io_error)? != migration.state_dir
    {
        return Err((
            1,
            "node address migration belongs to another config/state directory".into(),
        ));
    }
    let source = fs::read_to_string(config_path).map_err(io_error)?;
    if source != migration.old_source && source != migration.candidate_source {
        return Err((
            1,
            "cluster config changed during node address migration; refusing to overwrite it".into(),
        ));
    }
    let old =
        ClusterConfig::parse(&migration.old_source).map_err(|error| (2, error.to_string()))?;
    let new = ClusterConfig::parse(&migration.candidate_source)
        .map_err(|error| (2, error.to_string()))?;
    let changes = new
        .nodes
        .iter()
        .filter(|(id, node)| {
            old.nodes
                .get(*id)
                .is_some_and(|before| before.host != node.host)
        })
        .map(|(id, node)| (id.clone(), node.host.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut expected =
        ClusterConfig::parse(&address_candidate(&migration.old_source, &old, &changes)?)
            .map_err(|error| (2, error.to_string()))?;
    for (node_id, node) in &mut expected.nodes {
        node.remote_binary = new
            .nodes
            .get(node_id)
            .ok_or_else(|| (1, "address migration cannot remove nodes".into()))?
            .remote_binary
            .clone();
    }
    if expected != new {
        return Err((1, "node address migration contains changes beyond node addresses and verified Agent artifacts".into()));
    }
    Ok((old, new))
}

fn stage_address_agents(
    config: &ClusterConfig,
    source: &str,
    operation_id: &str,
) -> AppResult<String> {
    let mut candidate = source.to_owned();
    for (node_id, node) in &config.nodes {
        let destination = if node.transport == Transport::Local {
            std::env::current_exe()
                .map_err(io_error)?
                .canonicalize()
                .map_err(io_error)?
                .to_string_lossy()
                .into_owned()
        } else {
            let facts = read_remote_facts(node)?;
            let binary = select_local_binary(&facts.arch)?;
            let digest = local_sha256(&binary)?;
            let home = checked_remote_path(&facts.home)?;
            let destination = format!(
                "{home}/.local/share/macluster/clusters/{}/bin/{digest}/macluster",
                config.share_uuid
            );
            let mut staged = node.clone();
            staged.remote_binary = destination.clone();
            ensure_remote_binary(&staged, &binary, &facts.version, operation_id)?;
            destination
        };
        candidate = replace_node_string_key(&candidate, node_id, "remote_binary", &destination)?;
    }
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

#[cfg(test)]
fn address_unmount_script(
    requests: &[ClientUnmountRequest],
    aliases: &[(PathBuf, PathBuf)],
) -> String {
    let awk = shell_quote(client_mount_status_awk_script());
    let mut script = String::from("set -eu\n");
    for request in requests {
        script.push_str(&crate::nfs_recovery::cleanup_script(
            &request.source,
            &request.mount_root,
            &request.share_uuid,
        ));
    }
    for request in requests {
        script.push_str("mounts=$(/sbin/mount)\n");
        append_client_mount_status(&mut script, &awk, request);
        script.push_str("case \"$mount_status\" in expected|none) ;; *) echo 'managed mount source changed before address migration' >&2; exit 1 ;; esac\n");
    }
    for request in requests {
        script.push_str("mounts=$(/sbin/mount)\n");
        append_client_mount_status(&mut script, &awk, request);
        script.push_str(&format!(
            "case \"$mount_status\" in expected) /sbin/umount -f {} ;; none) ;; *) echo 'managed mount source changed during address migration' >&2; exit 1 ;; esac\n",
            shell_quote(&request.mount_root.to_string_lossy())
        ));
    }
    for (alias, target) in aliases {
        if alias != target {
            script.push_str(&client_alias_cleanup_snippet(alias, target));
        }
    }
    for (alias, target) in aliases {
        if alias != target {
            script.push_str(&client_alias_verification_snippet(alias, target));
        }
    }
    script
}

fn cleanup_address_nfs(
    old: &ClusterConfig,
    node_id: &str,
    connection: &NodeConfig,
) -> AppResult<()> {
    let (requests, aliases) = client_nfs_cleanup_plan(old, node_id);
    // The obsolete server/client IP can make even a marker read hang. At this
    // point both machines are verified and user tasks are stopped. Match the
    // exact original NFS source/type/target from the mount table before detaching.
    // No shared directories or data files are removed.
    let mounts = requests
        .iter()
        .map(|request| NfsMount {
            source: request.source.clone(),
            target: request.mount_root.to_string_lossy().into_owned(),
            share_uuid: request.share_uuid.clone(),
            alias: None,
            allow_existing_contents: false,
        })
        .collect::<Vec<_>>();
    let aliases = aliases
        .iter()
        .map(|(path, target)| NfsAlias {
            path: path.to_string_lossy().into_owned(),
            target: target.to_string_lossy().into_owned(),
        })
        .collect::<Vec<_>>();
    unmount_managed_nfs(
        connection,
        &mounts,
        &aliases,
        true,
        "detach exact obsolete NFS mounts before changing node addresses",
    )
    .map_err(|error| (1, error))?;
    let output = ssh_output(connection, "/sbin/mount", None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("cannot verify obsolete NFS detachment", &output),
        ));
    }
    for request in &requests {
        if named_share_mount_status(
            &String::from_utf8_lossy(&output.stdout),
            &request.source,
            &request.mount_root.to_string_lossy(),
        ) != NamedShareMountStatus::NotMounted
        {
            return Err((
                1,
                format!(
                    "mount {} remains occupied after address migration cleanup",
                    request.mount_root.display()
                ),
            ));
        }
    }
    Ok(())
}

fn migration_preflight(
    config_path: &Path,
    old: &ClusterConfig,
    new: &ClusterConfig,
) -> AppResult<()> {
    verify_registered_node_identities(new)?;
    for (node_id, connection) in &new.nodes {
        let mut agent = connection.clone();
        agent.remote_binary = old.nodes[node_id].remote_binary.clone();
        agent.remote_config = old.nodes[node_id].remote_config.clone();
        if let Some(status) = remote_execution_status(&agent, node_id, config_path)?
            && status.phase != RuntimePhase::Idle
        {
            return Err((
                1,
                format!(
                    "address migration is waiting for node {node_id} to finish its active execution ({:?})",
                    status.phase
                ),
            ));
        }
    }
    Ok(())
}

fn begin_migration(
    config_path: &Path,
    state_dir: &Path,
    mut migration: Migration,
) -> AppResult<bool> {
    let maintenance = acquire_node_maintenance(config_path, state_dir, MAINTENANCE_OPERATION)?;
    let (old, new) = checked_migration(config_path, state_dir, &migration)?;
    MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(io_error)?;
    let state = read_admin_state(&state_dir.join("node-admin.json"), config_path, state_dir)?;
    ensure_no_pending_admin_operation(&state)?;
    migration_preflight(config_path, &old, &new)?;
    migration.candidate_source =
        stage_address_agents(&new, &migration.candidate_source, &migration.operation_id)?;
    let new = ClusterConfig::parse(&migration.candidate_source)
        .map_err(|error| (2, error.to_string()))?;
    write_json(&state_dir.join(MIGRATION_FILE), &migration)?;
    run_migration(config_path, state_dir, migration, old, new)?;
    Ok(maintenance.controller_was_running)
}

fn resume_migration(config_path: &Path, state_dir: &Path, migration: Migration) -> AppResult<bool> {
    let maintenance = acquire_node_maintenance(config_path, state_dir, MAINTENANCE_OPERATION)?;
    let (old, new) = checked_migration(config_path, state_dir, &migration)?;
    migration_preflight(config_path, &old, &new)?;
    run_migration(config_path, state_dir, migration, old, new)?;
    Ok(maintenance.controller_was_running)
}

fn run_migration(
    config_path: &Path,
    state_dir: &Path,
    mut migration: Migration,
    old: ClusterConfig,
    new: ClusterConfig,
) -> AppResult<()> {
    let path = state_dir.join(MIGRATION_FILE);
    let result = (|| -> AppResult<()> {
        if migration.phase == "PLANNED" {
            for (node_id, connection) in &new.nodes {
                let step = format!("unmounted:{node_id}");
                if migration.completed.contains(&step) {
                    continue;
                }
                cleanup_address_nfs(&old, node_id, connection)?;
                migration.completed.insert(step);
                write_json(&path, &migration)?;
            }
            migration.phase = "EXPORTS".into();
            write_json(&path, &migration)?;
        }
        if migration.phase == "EXPORTS" {
            let old_groups = export_groups(&old);
            for (server_id, requests) in export_groups(&new) {
                let step = format!("exports:{server_id}");
                if migration.completed.contains(&step) {
                    continue;
                }
                let server = &new.nodes[&server_id];
                let (original, pending) = read_nfs_exports_update_baseline(server)?;
                let candidate = migrated_exports(
                    &original,
                    old_groups.get(&server_id).map_or(&[], Vec::as_slice),
                    &requests,
                )
                .map_err(|error| (1, error))?;
                if original != candidate || pending {
                    update_nfs_exports(
                        server,
                        &candidate,
                        &original,
                        &migration.operation_id,
                        "migrate managed NFS client addresses and reload exports",
                    )
                    .map_err(|error| (1, error))?;
                }
                migration.completed.insert(step);
                write_json(&path, &migration)?;
            }
            migration.phase = "MOUNTS".into();
            write_json(&path, &migration)?;
        }
        if migration.phase == "MOUNTS" {
            // Address migration can return a former login Mac to the compute
            // pool. Claim its idle Agent state and use the same guarded
            // primary-path reuse flow as normal enrollment, so a local
            // /Users/Shared/macluster directory is preserved before NFS is
            // mounted over it.
            let controller =
                super::migration_controller_epoch(state_dir).map_err(|error| (1, error))?;
            for (node_id, connection) in &new.nodes {
                let step = format!("mounted:{node_id}");
                if migration.completed.contains(&step) {
                    continue;
                }
                super::configure_node_nfs_resources_with_claim(
                    &new,
                    node_id,
                    connection,
                    &migration.operation_id,
                    &mut false,
                    &mut BTreeSet::new(),
                    None,
                    BTreeMap::new(),
                    Some(controller),
                )
                .map_err(|error| (1, error))?;
                migration.completed.insert(step);
                write_json(&path, &migration)?;
            }
            migration.phase = "SYNC".into();
            write_json(&path, &migration)?;
        }
        if migration.phase == "SYNC" {
            let peer_source = compatible_agent_config(&migration.candidate_source)?;
            for (node_id, connection) in &new.nodes {
                if connection.transport == Transport::Local {
                    continue;
                }
                let step = format!("synced:{node_id}");
                if migration.completed.contains(&step) {
                    continue;
                }
                let facts = read_remote_facts(connection)?;
                let home = checked_remote_path(&facts.home)?;
                let destination = connection
                    .remote_config
                    .clone()
                    .unwrap_or_else(|| format!("{home}/.config/macluster/config.toml"));
                sync_one_remote_config(
                    connection,
                    &destination,
                    &peer_source,
                    &new,
                    &migration.operation_id,
                    state_dir,
                    Some(&old),
                    None,
                )?;
                migration.completed.insert(step);
                write_json(&path, &migration)?;
            }
            migration.phase = "COMMITTING".into();
            write_json(&path, &migration)?;
        }
        if migration.phase != "COMMITTING" {
            return Err((
                1,
                format!("unrecognized address migration phase {}", migration.phase),
            ));
        }
        let current = fs::read_to_string(config_path).map_err(io_error)?;
        if current == migration.old_source {
            backup_config(config_path, &migration.operation_id)?;
            atomic_write(config_path, migration.candidate_source.as_bytes())?;
        } else if current != migration.candidate_source {
            return Err((
                1,
                "cluster config changed before address migration commit".into(),
            ));
        }
        fs::remove_file(&path).map_err(io_error)?;
        eprintln!(
            "Node addresses and managed NFS mappings updated; existing node IDs, queues and job records were preserved."
        );
        Ok(())
    })();
    result.map_err(|(code, error)| (code, format!("node address migration is paused in phase {}: {error}. Progress is saved in {}; rerun the command to resume. Submissions remain blocked until migration completes", migration.phase, path.display())))
}

pub(crate) fn refresh_node_addresses(
    config_path: &Path,
    state_dir: &Path,
    force: bool,
) -> AppResult<bool> {
    check_addresses(config_path, state_dir, force, true)
}

pub(crate) fn prepare_node_address_migration(
    config_path: &Path,
    state_dir: &Path,
) -> AppResult<bool> {
    check_addresses(config_path, state_dir, false, false)
}

pub(crate) fn address_migration_pending(state_dir: &Path) -> bool {
    state_dir.join(MIGRATION_FILE).exists() || state_dir.join(PROPOSAL_FILE).exists()
}

pub(crate) fn address_migration_has_active_jobs(state_dir: &Path) -> AppResult<bool> {
    if !state_dir.join("controller.sqlite3").is_file() {
        return Ok(false);
    }
    let storage = macluster_core::storage::ReadOnlyJobStore::open(state_dir)
        .map_err(|error| (1, error.to_string()))?;
    let jobs = storage
        .list_jobs(None)
        .map_err(|error| (1, error.to_string()))?;
    Ok(jobs.iter().any(|job| {
        matches!(
            job.state,
            macluster_protocol::types::JobState::Starting
                | macluster_protocol::types::JobState::Running
                | macluster_protocol::types::JobState::Cancelling
        )
    }))
}

pub(crate) struct AddressWatcher {
    stop: Arc<AtomicBool>,
    pending: Arc<AtomicBool>,
}

impl AddressWatcher {
    pub(crate) fn pending_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.pending)
    }
}

impl Drop for AddressWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub(crate) fn watch_node_addresses(
    config_path: PathBuf,
    state_dir: PathBuf,
) -> AppResult<AddressWatcher> {
    let watcher = AddressWatcher {
        stop: Arc::new(AtomicBool::new(false)),
        pending: Arc::new(AtomicBool::new(address_migration_pending(&state_dir))),
    };
    let stop = Arc::clone(&watcher.stop);
    let pending = Arc::clone(&watcher.pending);
    thread::Builder::new()
        .name("macluster-node-addresses".into())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for _ in 0..30 {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                match prepare_node_address_migration(&config_path, &state_dir) {
                    Ok(found) => pending.store(found, Ordering::SeqCst),
                    Err((_, error)) => {
                        eprintln!("macluster: automatic node address discovery: {error}")
                    }
                }
            }
        })
        .map_err(io_error)?;
    Ok(watcher)
}

fn check_addresses(
    config_path: &Path,
    state_dir: &Path,
    force: bool,
    apply: bool,
) -> AppResult<bool> {
    if !config_path.is_file() {
        return Ok(false);
    }
    let resolved_config = config_path.canonicalize().map_err(io_error)?;
    let config_path = resolved_config.as_path();
    let source = fs::read_to_string(config_path).map_err(io_error)?;
    let config = match ClusterConfig::parse(&source) {
        Ok(config) => config,
        Err(_) => return Ok(false),
    };
    let Some((local_id, local_node)) = config
        .nodes
        .iter()
        .find(|(_, node)| node.transport == Transport::Local)
    else {
        return Ok(false);
    };
    if local_node
        .host
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback())
    {
        return Ok(false);
    }
    if !local_node.machine_uuid.as_deref().is_some_and(|uuid| {
        local_platform_uuid().is_ok_and(|actual| uuid.eq_ignore_ascii_case(&actual))
    }) {
        return Ok(false);
    }
    crate::init::reset::ensure_no_reset_in_progress(config_path, state_dir)?;
    let migration_path = state_dir.join(MIGRATION_FILE);
    if let Some(migration) = read_private_json::<Migration>(&migration_path)? {
        return if apply {
            resume_migration(config_path, state_dir, migration)
        } else {
            Ok(true)
        };
    }
    let proposal_path = state_dir.join(PROPOSAL_FILE);
    if let Some(migration) = read_private_json::<Migration>(&proposal_path)? {
        if migration.old_source == source {
            if !apply {
                return Ok(true);
            }
            let result = begin_migration(config_path, state_dir, migration)?;
            remove_stale_proposal(&proposal_path)?;
            return Ok(result);
        }
        remove_stale_proposal(&proposal_path)?;
    }
    let inventory_path = state_dir.join(INVENTORY_FILE);
    let mut inventory = read_private_json::<Inventory>(&inventory_path)?
        .filter(|record| record.share_uuid == config.share_uuid)
        .unwrap_or_default();
    let allow_full_subnet_scan =
        full_subnet_scan_due(inventory.last_subnet_scan_ms, now_ms(), force);
    let interfaces = local_interfaces()?;
    let local_current = interfaces
        .iter()
        .any(|interface| interface.address.to_string() == local_node.host);
    if !force
        && local_current
        && config.nodes.iter().all(|(id, node)| {
            inventory
                .nodes
                .get(id)
                .is_some_and(|record| record.host == node.host)
        })
        && inventory.config_digest
            == sha256_hex(source.as_bytes()).map_err(|error| (1, error.to_string()))?
        && inventory.checked_ms <= now_ms()
        && now_ms().saturating_sub(inventory.checked_ms) < CHECK_INTERVAL_MS
    {
        return Ok(false);
    }
    let mut replacements = BTreeMap::new();
    let old = local_node
        .host
        .parse::<Ipv4Addr>()
        .map_err(|_| (2, "registered login address is not IPv4".into()))?;
    let local_interface = if local_current {
        interfaces.iter().find(|interface| interface.address == old)
    } else {
        matching_interface(
            old,
            &interfaces,
            inventory
                .nodes
                .get(local_id)
                .and_then(|record| record.mac.as_deref()),
        )
    };
    if let Some(interface) = local_interface {
        if interface.address.to_string() != local_node.host {
            replacements.insert(local_id.clone(), interface.address.to_string());
        }
        inventory.nodes.insert(
            local_id.clone(),
            AddressRecord {
                machine_uuid: local_node.machine_uuid.clone().unwrap(),
                host: interface.address.to_string(),
                mac: interface.mac.clone(),
            },
        );
    } else if !local_current {
        return Err((1, "login address changed but no unambiguous interface remains in the registered subnet; select the intended cluster interface explicitly".into()));
    }
    let mut unreachable = Vec::new();
    let mut scanned_full_subnet = false;
    for (node_id, node) in &config.nodes {
        if node.transport != Transport::Ssh {
            continue;
        }
        let known = inventory.nodes.get(node_id).filter(|record| {
            node.machine_uuid
                .as_deref()
                .is_some_and(|uuid| uuid.eq_ignore_ascii_case(&record.machine_uuid))
        });
        let (discovered, scanned) =
            discover_remote(node, known, &interfaces, force, allow_full_subnet_scan)?;
        scanned_full_subnet |= scanned;
        match discovered {
            Some((connection, record)) => {
                if let Some((pin, _)) = node.ssh_host_key_pin()
                    && pin.is_file()
                {
                    let path = pin.with_extension("address");
                    let previous = fs::read(&path).ok();
                    let payload =
                        connection_cache_payload(&node.host, &connection.host, previous.as_deref());
                    if previous.as_deref() != Some(payload.as_bytes()) {
                        atomic_write(&path, payload.as_bytes())?;
                    }
                }
                if connection.host != node.host {
                    replacements.insert(node_id.clone(), connection.host);
                }
                inventory.nodes.insert(node_id.clone(), record);
            }
            None => unreachable.push(node_id.clone()),
        }
    }
    inventory.share_uuid = config.share_uuid.clone();
    inventory.config_digest =
        sha256_hex(source.as_bytes()).map_err(|error| (1, error.to_string()))?;
    inventory.checked_ms = now_ms();
    if scanned_full_subnet {
        inventory.last_subnet_scan_ms = inventory.checked_ms;
    }
    if replacements.is_empty() {
        write_json(&inventory_path, &inventory)?;
        return Ok(false);
    }
    if !unreachable.is_empty() {
        write_json(&inventory_path, &inventory)?;
        return Err((
            1,
            format!(
                "node address changes were discovered, but {} could not be verified; address/NFS migration was deferred",
                unreachable.join(", ")
            ),
        ));
    }
    let candidate = address_candidate(&source, &config, &replacements)?;
    eprintln!("Node address changes detected:");
    for (node_id, address) in &replacements {
        eprintln!("  {node_id}: {} -> {address}", config.nodes[node_id].host);
    }
    let canonical_config = config_path.canonicalize().map_err(io_error)?;
    fs::create_dir_all(state_dir).map_err(io_error)?;
    let migration = Migration {
        operation_id: Id128::random().to_string(),
        config_path: canonical_config,
        state_dir: state_dir.canonicalize().map_err(io_error)?,
        old_source: source,
        candidate_source: candidate,
        phase: "PLANNED".into(),
        completed: BTreeSet::new(),
    };
    if !apply {
        write_json(&inventory_path, &inventory)?;
        write_json(&proposal_path, &migration)?;
        return Ok(true);
    }
    let result = begin_migration(config_path, state_dir, migration)?;
    write_json(&inventory_path, &inventory)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_connection_cache_keeps_recent_origins_for_long_running_clients() {
        let first = connection_cache_payload("192.0.2.1", "192.0.2.3", None);
        let committed = connection_cache_payload("192.0.2.3", "192.0.2.3", Some(first.as_bytes()));
        assert_eq!(committed, "192.0.2.3 192.0.2.3 192.0.2.1\n");
        let moved_again =
            connection_cache_payload("192.0.2.3", "192.0.2.5", Some(committed.as_bytes()));
        assert_eq!(moved_again, "192.0.2.3 192.0.2.5 192.0.2.1\n");
    }

    #[test]
    fn stale_proposal_cleanup_is_safe_when_another_thread_already_removed_it() {
        let root =
            std::env::temp_dir().join(format!("macluster-stale-proposal-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let proposal = root.join(PROPOSAL_FILE);
        fs::write(&proposal, b"proposal").unwrap();

        assert!(remove_stale_proposal(&proposal).is_ok());
        assert!(remove_stale_proposal(&proposal).is_ok());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_nfs_cleanup_uses_exact_mount_table_identity_without_reading_a_dead_server() {
        let root = std::env::temp_dir().join(format!("macluster-stale-nfs-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let mount_root = root.join("mount");
        fs::create_dir(&mount_root).unwrap();
        fs::write(mount_root.join("keep.txt"), "preserve underlying files").unwrap();
        let table = root.join("table");
        let log = root.join("unmounted");
        let fake_mount = root.join("mount-tool");
        let fake_umount = root.join("umount-tool");
        fs::write(
            &fake_mount,
            "#!/bin/sh\n/bin/cat \"$MACLUSTER_TEST_MOUNTS\"\n",
        )
        .unwrap();
        fs::write(&fake_umount, "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$MACLUSTER_TEST_UNMOUNTS\"\n: > \"$MACLUSTER_TEST_MOUNTS\"\n").unwrap();
        for tool in [&fake_mount, &fake_umount] {
            fs::set_permissions(tool, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let request = ClientUnmountRequest {
            source: "192.0.2.1:/share".into(),
            mount_root: mount_root.clone(),
            share_uuid: "unreadable-marker".into(),
            label: "stale shared root".into(),
            allow_existing_contents: false,
        };
        let script = address_unmount_script(&[request], &[])
            .replace("/sbin/mount", &shell_quote(&fake_mount.to_string_lossy()))
            .replace("/sbin/umount", &shell_quote(&fake_umount.to_string_lossy()));
        fs::write(
            &table,
            format!(
                "192.0.2.1:/share on {} (nfs, nodev)\n",
                mount_root.display()
            ),
        )
        .unwrap();
        let run = || {
            Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .env("MACLUSTER_TEST_MOUNTS", &table)
                .env("MACLUSTER_TEST_UNMOUNTS", &log)
                .output()
                .unwrap()
        };
        let first = run();
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            format!("-f\n{}\n", mount_root.display())
        );
        fs::write(&log, "").unwrap();
        fs::write(
            &table,
            format!("/dev/disk8s1 on {} (apfs, local)\n", mount_root.display()),
        )
        .unwrap();
        assert!(!run().status.success());
        assert!(fs::read(&log).unwrap().is_empty());
        assert_eq!(
            fs::read_to_string(mount_root.join("keep.txt")).unwrap(),
            "preserve underlying files"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn address_maintenance_keeps_terminal_output_but_still_blocks_running_jobs() {
        use macluster_protocol::identifiers::RequestId;
        use macluster_protocol::types::{JobSpec, JobState};
        let root = std::env::temp_dir().join(format!(
            "macluster-address-retained-output-{}",
            Id128::random()
        ));
        let storage = Storage::open(&root).unwrap();
        let snapshot = storage.stage_snapshot(b"true\n").unwrap();
        let spec: JobSpec = serde_json::from_value(serde_json::json!({
            "queue":"compute", "node":null, "name":"retained", "cwd":"/tmp/shared",
            "stdout_path":"/tmp/shared/out", "stderr_path":"/tmp/shared/err", "walltime_secs":null, "env":{}, "snapshot":snapshot
        })).unwrap();
        let job = storage.submit_once(RequestId::random(), spec).unwrap();
        storage
            .reserve_job(job.id, NodeId::new("worker").unwrap())
            .unwrap();
        storage.mark_running(job.id).unwrap();
        assert!(ensure_maintenance_jobs_drained(&root, MAINTENANCE_OPERATION, false).is_err());
        storage
            .finish_job(job.id, JobState::Completed, Some(0), None)
            .unwrap();
        storage.set_log_sync_pending(job.id, true).unwrap();
        assert!(ensure_maintenance_jobs_drained(&root, MAINTENANCE_OPERATION, false).is_ok());
        assert!(ensure_maintenance_jobs_drained(&root, "mnode --remove", false).is_err());
        assert!(storage.get_job(job.id).unwrap().unwrap().log_sync_pending);
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nfs_address_migration_is_idempotent_and_keeps_operator_exports() {
        let old = NfsExportRequest {
            root: "/Users/Shared/macluster".into(),
            client_ip: "192.168.2.1".into(),
            share_uuid: "share".into(),
            node_id: "worker".into(),
        };
        let mut new = old.clone();
        new.client_ip = "192.168.2.3".into();
        let original = "# operator\n/Volumes/Other 192.168.2.9\n# macluster-managed share worker\n/Users/Shared/macluster 192.168.2.1\n";
        let expected = "# operator\n/Volumes/Other 192.168.2.9\n# macluster-managed share worker\n/Users/Shared/macluster 192.168.2.3\n";
        assert_eq!(
            migrated_exports(
                original,
                std::slice::from_ref(&old),
                std::slice::from_ref(&new)
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            migrated_exports(
                expected,
                std::slice::from_ref(&old),
                std::slice::from_ref(&new)
            )
            .unwrap(),
            expected
        );
        assert!(
            migrated_exports(
                &original.replace("macluster 192.168.2.1", "macluster 192.168.2.8"),
                &[old],
                &[new]
            )
            .is_err()
        );
    }

    #[test]
    fn simultaneous_node_address_changes_preserve_ids_queues_and_storage_paths() {
        let source = "[cluster]\nname=\"test\"\ndefault_queue=\"compute\"\nshared_root=\"/tmp/macluster-shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"arm-a\"\nprotocol_version=1\n[queues.compute]\nnodes=[\"arm-a\",\"arm-b\"]\nscheduler=\"fifo\"\n[nodes.arm-a]\nhost=\"192.0.2.10\"\ntransport=\"ssh\"\n[nodes.arm-b]\nhost=\"192.0.2.11\"\ntransport=\"ssh\"\n";
        let config = ClusterConfig::parse(source).unwrap();
        let replacements = BTreeMap::from([
            ("arm-a".into(), "192.0.2.11".into()),
            ("arm-b".into(), "192.0.2.10".into()),
        ]);
        let migrated =
            ClusterConfig::parse(&address_candidate(source, &config, &replacements).unwrap())
                .unwrap();
        assert_eq!(migrated.nodes["arm-a"].host, "192.0.2.11");
        assert_eq!(migrated.nodes["arm-b"].host, "192.0.2.10");
        assert_eq!(migrated.queues, config.queues);
        assert_eq!(migrated.shared_root, config.shared_root);
        assert_eq!(migrated.storage_server, config.storage_server);
        assert!(
            address_candidate(
                source,
                &config,
                &BTreeMap::from([("arm-a".into(), "192.0.2.11".into())])
            )
            .is_err()
        );
    }

    #[test]
    fn mac_and_arp_parsing_accept_short_octets_but_not_incomplete_neighbors() {
        assert_eq!(
            normalize_mac("36:52:b2:4:bb:80").as_deref(),
            Some("36:52:b2:04:bb:80")
        );
        assert!(normalize_mac("ff:ff:ff:ff:ff:ff").is_none());
        let entries = parse_neighbors(
            "? (192.168.2.3) at 36:52:b2:4:bb:80 on bridge0 ifscope [bridge]\n? (192.168.2.4) at (incomplete) on bridge0\n",
        );
        assert_eq!(
            entries,
            vec![(
                "192.168.2.3".parse::<Ipv4Addr>().unwrap(),
                "36:52:b2:04:bb:80".into()
            )]
        );
    }

    #[test]
    fn interface_selection_uses_real_netmask_and_refuses_ambiguous_matches() {
        let interfaces = parse_interfaces(
            "bridge0: flags=8863<UP,BROADCAST,RUNNING>\n\tether 36:3d:96:0:52:80\n\tinet 192.168.2.1 netmask 0xffffff80 broadcast 192.168.2.127\nen0: flags=8863<UP,RUNNING>\n\tether 32:08:ef:e3:41:8e\n\tinet 192.168.6.235 netmask 0xffffff00\n",
        );
        let interface =
            matching_interface("192.168.2.2".parse().unwrap(), &interfaces, None).unwrap();
        assert_eq!(interface.interface, "bridge0");
        assert!(!interface.contains("192.168.2.200".parse().unwrap()));
        let mut ambiguous = interfaces.clone();
        ambiguous.push(InterfaceAddress {
            interface: "en9".into(),
            address: "192.168.2.5".parse().unwrap(),
            mask: 0xffffff80,
            mac: None,
        });
        assert!(matching_interface("192.168.2.2".parse().unwrap(), &ambiguous, None).is_none());
        assert_eq!(
            matching_interface(
                "192.168.2.2".parse().unwrap(),
                &ambiguous,
                Some("36:3d:96:00:52:80")
            )
            .unwrap()
            .interface,
            "bridge0"
        );
    }

    #[test]
    fn subnet_scan_prioritizes_recorded_mac_and_excludes_other_networks_and_this_mac() {
        let interface = InterfaceAddress {
            interface: "bridge0".into(),
            address: "192.168.2.1".parse().unwrap(),
            mask: 0xffffff00,
            mac: None,
        };
        let entries = vec![
            ("192.168.2.3".parse().unwrap(), "36:52:b2:04:bb:80".into()),
            ("192.168.6.3".parse().unwrap(), "36:52:b2:04:bb:80".into()),
        ];
        let (preferred, rest) = subnet_candidates(
            &interface,
            std::slice::from_ref(&interface),
            &entries,
            Some("36:52:b2:04:bb:80"),
        );
        assert_eq!(preferred, vec!["192.168.2.3".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(rest.len(), 252);
        assert!(!rest.contains(&interface.address));
        assert!(!rest.contains(&"192.168.2.255".parse().unwrap()));
        assert!(rest.iter().all(|address| interface.contains(*address)));
    }

    #[test]
    fn full_subnet_scan_is_rate_limited_but_can_be_forced() {
        let last_scan_ms = 1_000;
        assert!(!full_subnet_scan_due(
            last_scan_ms,
            last_scan_ms + SUBNET_SCAN_INTERVAL_MS - 1,
            false
        ));
        assert!(full_subnet_scan_due(
            last_scan_ms,
            last_scan_ms + SUBNET_SCAN_INTERVAL_MS,
            false
        ));
        assert!(full_subnet_scan_due(last_scan_ms, last_scan_ms + 1, true));
        assert!(full_subnet_scan_due(0, 1, false));
        assert!(!full_subnet_scan_due(last_scan_ms, last_scan_ms - 1, false));
    }
}
