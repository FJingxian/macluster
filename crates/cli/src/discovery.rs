use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    net::Ipv4Addr,
    path::Path,
    time::{Duration, Instant},
};

use macluster_core::config::{ClusterConfig, Transport};
use macluster_protocol::identifiers::Id128;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Deserialize;

const SERVICE_TYPE: &str = "_macluster._tcp.local.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRecord {
    pub instance: String,
    pub cluster_uuid: String,
    pub cluster_name: String,
    pub protocol_version: u16,
    pub controller_build: String,
    pub ssh_host_fingerprint: String,
    pub transport: String,
    pub ssh_user: Option<String>,
    pub resolved_address: Option<String>,
    pub ssh_port: Option<u16>,
}

impl DiscoveryRecord {
    pub fn from_properties(
        instance: impl Into<String>,
        properties: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let instance = instance.into();
        let value = |key: &str| {
            properties
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| format!("discovery record is missing '{key}'"))
        };
        let validate = |value: &str, key: &str| {
            if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
                return Err(format!("discovery field '{key}' is invalid"));
            }
            Ok(())
        };
        let cluster_uuid = value("cluster_uuid")?;
        Id128::parse(cluster_uuid).map_err(|_| "discovery cluster UUID is invalid".to_owned())?;
        let cluster_name = value("cluster_name")?;
        let controller_build = value("controller_build")?;
        let ssh_host_fingerprint = value("ssh_host_fingerprint")?;
        let transport = value("transport")?;
        for (key, item) in [
            ("instance", instance.as_str()),
            ("cluster_name", cluster_name),
            ("controller_build", controller_build),
            ("ssh_host_fingerprint", ssh_host_fingerprint),
        ] {
            validate(item, key)?;
        }
        if !ssh_host_fingerprint.starts_with("SHA256:") || transport != "ssh" {
            return Err("discovery transport identity is invalid".into());
        }
        let ssh_user = properties.get("ssh_user").cloned();
        if let Some(user) = ssh_user.as_deref()
            && !valid_ssh_user(user)
        {
            return Err("discovery SSH user is invalid".into());
        }
        let protocol_version = value("protocol_version")?
            .parse::<u16>()
            .map_err(|_| "discovery protocol version is invalid".to_owned())?;
        Ok(Self {
            instance,
            cluster_uuid: cluster_uuid.to_ascii_lowercase(),
            cluster_name: cluster_name.into(),
            protocol_version,
            controller_build: controller_build.into(),
            ssh_host_fingerprint: ssh_host_fingerprint.into(),
            transport: transport.into(),
            ssh_user,
            resolved_address: None,
            ssh_port: None,
        })
    }

    pub fn properties(&self) -> BTreeMap<String, String> {
        let mut properties = BTreeMap::from([
            ("cluster_uuid".into(), self.cluster_uuid.clone()),
            ("cluster_name".into(), self.cluster_name.clone()),
            ("protocol_version".into(), self.protocol_version.to_string()),
            ("controller_build".into(), self.controller_build.clone()),
            (
                "ssh_host_fingerprint".into(),
                self.ssh_host_fingerprint.clone(),
            ),
            ("transport".into(), self.transport.clone()),
        ]);
        if let Some(ssh_user) = self.ssh_user.as_ref() {
            properties.insert("ssh_user".into(), ssh_user.clone());
        }
        properties
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalClusterCandidate {
    pub cluster_uuid: String,
    pub cluster_name: String,
    pub ssh_user: String,
    pub host: String,
    pub ssh_port: u16,
}

#[derive(Deserialize)]
struct LocalAgentState {
    #[serde(default)]
    owner_namespace: Option<String>,
}

pub fn discover_local_cluster_candidates(
    home: &Path,
    mount_table: &str,
    local_addresses: &BTreeSet<Ipv4Addr>,
    fallback_user: &str,
) -> Result<Vec<LocalClusterCandidate>, String> {
    let state_path = home.join("Library/Application Support/macluster/agent/agent-state.json");
    let state_bytes = match fs::read(&state_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read local Agent state: {error}")),
    };
    let state: LocalAgentState = serde_json::from_slice(&state_bytes)
        .map_err(|error| format!("cannot parse local Agent state: {error}"))?;
    let Ok(cluster_uuid) = Id128::parse(state.owner_namespace.as_deref().unwrap_or_default())
    else {
        return Ok(Vec::new());
    };
    let cluster_uuid = cluster_uuid.to_string();
    let mounted = nfs_mount_sources(mount_table);
    let agents_root = home
        .join(".config/macluster/clusters")
        .join(&cluster_uuid)
        .join("agents");
    let entries = match fs::read_dir(&agents_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot inspect current Agent configs: {error}")),
    };
    let mut candidates = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path().join("config.toml");
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "cannot read current Agent config {}: {error}",
                    path.display()
                ));
            }
        };
        let config = match ClusterConfig::parse(&contents) {
            Ok(config) if config.share_uuid.eq_ignore_ascii_case(&cluster_uuid) => config,
            Ok(_) => continue,
            Err(_) => continue,
        };
        let Some((_, login)) = config
            .nodes
            .iter()
            .find(|(id, node)| config.is_login_node(id) && node.transport == Transport::Local)
        else {
            continue;
        };
        if login.host == "localhost"
            || login
                .host
                .parse::<Ipv4Addr>()
                .is_ok_and(|address| local_addresses.contains(&address))
        {
            continue;
        }
        let mut paths = config
            .shares
            .values()
            .map(|share| share.source_root.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        paths.push(login.remote_binary.clone());
        paths.extend(login.remote_config.clone());
        paths.extend(
            mounted
                .iter()
                .filter(|(host, _)| host == &login.host)
                .map(|(_, source)| source.clone()),
        );
        let users = paths
            .iter()
            .filter_map(|path| ssh_user_from_path(path))
            .collect::<BTreeSet<_>>();
        let users = if users.is_empty() && valid_ssh_user(fallback_user) {
            BTreeSet::from([fallback_user.to_owned()])
        } else {
            users
        };
        for ssh_user in users {
            candidates.insert(LocalClusterCandidate {
                cluster_uuid: cluster_uuid.clone(),
                cluster_name: config.name.clone(),
                ssh_user,
                host: login.host.clone(),
                ssh_port: login.ssh_port.unwrap_or(22),
            });
        }
    }
    Ok(candidates.into_iter().collect())
}

fn nfs_mount_sources(mount_table: &str) -> Vec<(String, String)> {
    mount_table
        .lines()
        .filter(|line| line.contains("(nfs"))
        .filter_map(|line| {
            let (source, _) = line.split_once(" on ")?;
            let (host, root) = source.split_once(':')?;
            if host.is_empty() || root.is_empty() {
                return None;
            }
            Some((host.to_owned(), root.to_owned()))
        })
        .collect()
}

fn ssh_user_from_path(path: &str) -> Option<String> {
    let components = Path::new(path).components().collect::<Vec<_>>();
    for pair in components.windows(2) {
        if pair[0].as_os_str() == "Users" {
            let user = pair[1].as_os_str().to_str()?;
            if user != "Shared" && valid_ssh_user(user) {
                return Some(user.to_owned());
            }
        }
    }
    None
}

fn valid_ssh_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphanumeric() || byte == b'_'
            } else {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
            }
        })
}

pub fn fingerprint_matches(record: &DiscoveryRecord, expected: &str) -> bool {
    record.ssh_host_fingerprint == expected
}

pub fn merge_records(records: Vec<DiscoveryRecord>) -> Vec<DiscoveryRecord> {
    let mut seen = BTreeSet::new();
    records
        .into_iter()
        .filter(|record| seen.insert(record.cluster_uuid.clone()))
        .collect()
}

pub struct AdvertisementGuard {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for AdvertisementGuard {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

pub fn advertise_cluster(
    record: &DiscoveryRecord,
    hostname: &str,
    addresses: &str,
    ssh_port: u16,
) -> Result<AdvertisementGuard, String> {
    let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
    let host = format!("{}.local.", hostname.trim_end_matches(".local."));
    let instance = format!("{}-{}", record.cluster_name, &record.cluster_uuid[..8]);
    let properties = record.properties().into_iter().collect::<HashMap<_, _>>();
    let service = ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &host,
        addresses,
        ssh_port,
        properties,
    )
    .map_err(|error| error.to_string())?;
    let fullname = service.get_fullname().to_owned();
    daemon
        .register(service)
        .map_err(|error| error.to_string())?;
    Ok(AdvertisementGuard { daemon, fullname })
}

pub fn discover_clusters(timeout: Duration) -> Result<Vec<DiscoveryRecord>, String> {
    let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut records = Vec::new();
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let properties = info
                    .txt_properties
                    .iter()
                    .map(|property| (property.key().to_owned(), property.val_str().to_owned()))
                    .collect::<BTreeMap<_, _>>();
                if let Ok(mut record) =
                    DiscoveryRecord::from_properties(&info.fullname, &properties)
                {
                    record.resolved_address = info
                        .addresses
                        .iter()
                        .find(|address| address.is_ipv4())
                        .map(ToString::to_string);
                    record.ssh_port = Some(info.port);
                    records.push(record);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    Ok(merge_records(records))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        net::Ipv4Addr,
    };

    use macluster_protocol::identifiers::Id128;

    use super::{DiscoveryRecord, fingerprint_matches};

    fn properties() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "cluster_uuid".into(),
                "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            ),
            ("cluster_name".into(), "home".into()),
            ("protocol_version".into(), "2".into()),
            ("controller_build".into(), "macluster/0.2.0".into()),
            (
                "ssh_host_fingerprint".into(),
                "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCD".into(),
            ),
            ("transport".into(), "ssh".into()),
            ("ssh_user".into(), "loginuser".into()),
        ])
    }

    #[test]
    fn discovery_record_requires_uuid_name_build_and_fingerprint() {
        let record =
            DiscoveryRecord::from_properties("home._macluster._tcp.local.", &properties()).unwrap();
        assert_eq!(record.cluster_name, "home");
        assert_eq!(record.cluster_uuid, "f779bcf5-ea85-5caa-9579-74b395f3cce5");
        assert_eq!(record.ssh_user.as_deref(), Some("loginuser"));
        assert_eq!(
            record.properties().get("ssh_user").map(String::as_str),
            Some("loginuser")
        );
        assert!(fingerprint_matches(&record, &record.ssh_host_fingerprint));
    }

    #[test]
    fn discovery_rejects_unsafe_or_oversized_txt_fields() {
        let mut values = properties();
        values.insert("cluster_name".into(), "bad\nname".into());
        assert!(DiscoveryRecord::from_properties("bad", &values).is_err());
        values = properties();
        values.insert("controller_build".into(), "x".repeat(300));
        assert!(DiscoveryRecord::from_properties("bad", &values).is_err());
    }

    #[test]
    fn discovery_merges_duplicate_service_instances() {
        let mut values = properties();
        values.insert(
            "cluster_uuid".into(),
            "82d02835-f6ab-52b4-aaab-f90cafde9981".into(),
        );
        let first =
            DiscoveryRecord::from_properties("one._macluster._tcp.local.", &values).unwrap();
        let second =
            DiscoveryRecord::from_properties("two._macluster._tcp.local.", &values).unwrap();
        assert_eq!(super::merge_records(vec![first, second]).len(), 1);
    }

    #[test]
    fn paired_fingerprint_is_not_replaced_by_spoofed_record() {
        let record = DiscoveryRecord::from_properties("home", &properties()).unwrap();
        assert!(!fingerprint_matches(&record, "SHA256:spoofed"));
    }

    #[test]
    fn active_agent_config_discovers_the_current_login_and_ssh_account() {
        let root =
            std::env::temp_dir().join(format!("macluster-local-discovery-{}", Id128::random()));
        let cluster_uuid = "f779bcf5-ea85-5caa-9579-74b395f3cce5";
        let agent_dir = root
            .join(".config/macluster/clusters")
            .join(cluster_uuid)
            .join("agents/machine-1");
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(
            agent_dir.join("config.toml"),
            format!(
                r#"[cluster]
name = "home"
default_queue = "default"
login_node = "login-01"
shared_root = "/Users/Shared/macluster"
share_uuid = "{cluster_uuid}"
storage_server = "login-01"
protocol_version = 1

[queues.default]
nodes = ["login-01"]
scheduler = "fifo"

[nodes.login-01]
host = "192.0.2.1"
transport = "local"
remote_binary = "/Users/loginuser/bin/macluster"
machine_uuid = "01234567-89ab-cdef-0123-456789abcdef"
execution_uid = 501

[shares.tools]
server = "login-01"
source_root = "/Users/loginuser/tools"
mount_root = "/Users/Shared/tools"
share_uuid = "82d02835-f6ab-52b4-aaab-f90cafde9981"
"#
            ),
        )
        .unwrap();
        let state = root.join("Library/Application Support/macluster/agent");
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join("agent-state.json"),
            format!(r#"{{"owner_namespace":"{cluster_uuid}"}}"#),
        )
        .unwrap();

        let candidates = super::discover_local_cluster_candidates(
            &root,
            "",
            &BTreeSet::from([Ipv4Addr::new(192, 0, 2, 2)]),
            "worker",
        )
        .unwrap();
        assert_eq!(
            candidates,
            vec![super::LocalClusterCandidate {
                cluster_uuid: cluster_uuid.into(),
                cluster_name: "home".into(),
                ssh_user: "loginuser".into(),
                host: "192.0.2.1".into(),
                ssh_port: 22,
            }]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_discovery_ignores_a_login_address_on_this_machine() {
        let root = std::env::temp_dir().join(format!("macluster-local-self-{}", Id128::random()));
        let cluster_uuid = "55fb9b02-ce96-5a69-8ad3-356563eff27b";
        let agent_dir = root
            .join(".config/macluster/clusters")
            .join(cluster_uuid)
            .join("agents/machine-1");
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(
            agent_dir.join("config.toml"),
            format!(
                r#"[cluster]
name = "home"
default_queue = "default"
login_node = "login-01"
shared_root = "/Users/Shared/macluster"
share_uuid = "{cluster_uuid}"
storage_server = "login-01"
protocol_version = 1

[queues.default]
nodes = ["login-01"]
scheduler = "fifo"

[nodes.login-01]
host = "192.0.2.2"
transport = "local"
remote_binary = "/Users/worker/bin/macluster"
machine_uuid = "01234567-89ab-cdef-0123-456789abcdef"
execution_uid = 501
"#
            ),
        )
        .unwrap();
        let state = root.join("Library/Application Support/macluster/agent");
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join("agent-state.json"),
            format!(r#"{{"owner_namespace":"{cluster_uuid}"}}"#),
        )
        .unwrap();

        assert!(
            super::discover_local_cluster_candidates(
                &root,
                "",
                &BTreeSet::from([Ipv4Addr::new(192, 0, 2, 2)]),
                "worker",
            )
            .unwrap()
            .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
