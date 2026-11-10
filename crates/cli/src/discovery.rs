use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::{Duration, Instant},
};

use macluster_protocol::identifiers::Id128;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

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
        })
    }

    pub fn properties(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("cluster_uuid".into(), self.cluster_uuid.clone()),
            ("cluster_name".into(), self.cluster_name.clone()),
            ("protocol_version".into(), self.protocol_version.to_string()),
            ("controller_build".into(), self.controller_build.clone()),
            (
                "ssh_host_fingerprint".into(),
                self.ssh_host_fingerprint.clone(),
            ),
            ("transport".into(), self.transport.clone()),
        ])
    }
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
                if let Ok(record) = DiscoveryRecord::from_properties(&info.fullname, &properties) {
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
    use std::collections::BTreeMap;

    use super::{DiscoveryRecord, fingerprint_matches};

    fn properties() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "cluster_uuid".into(),
                "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            ),
            ("cluster_name".into(), "home".into()),
            ("protocol_version".into(), "2".into()),
            ("controller_build".into(), "macluster/0.1.8".into()),
            (
                "ssh_host_fingerprint".into(),
                "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCD".into(),
            ),
            ("transport".into(), "ssh".into()),
        ])
    }

    #[test]
    fn discovery_record_requires_uuid_name_build_and_fingerprint() {
        let record =
            DiscoveryRecord::from_properties("home._macluster._tcp.local.", &properties()).unwrap();
        assert_eq!(record.cluster_name, "home");
        assert_eq!(record.cluster_uuid, "f779bcf5-ea85-5caa-9579-74b395f3cce5");
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
}
