//! Narrow, versioned requests accepted by the privileged NFS administrator.

use std::{collections::BTreeSet, path::Path};

use crate::identifiers::Id128;
use serde::{Deserialize, Serialize};

pub const MAX_NFS_ADMIN_REQUEST_BYTES: usize = 1024 * 1024;
/// Wire version for requests handled by the privileged NFS service. Keep this
/// independent from the installed root-owned CLI implementation revision.
pub const NFS_ADMIN_SERVICE_VERSION: &str = "nfs-admin-1";
const MAX_BATCH_ITEMS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NfsAdminRequest {
    pub operation: NfsAdminOperation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NfsAdminOperation {
    Ping,
    Mount {
        mounts: Vec<NfsMount>,
    },
    Unmount {
        mounts: Vec<NfsMount>,
        aliases: Vec<NfsAlias>,
        #[serde(default)]
        force: bool,
    },
    RemoveMarker {
        source_root: String,
        share_uuid: String,
    },
    CheckMarker {
        source_root: String,
        share_uuid: String,
    },
    CheckAlias {
        path: String,
        target: String,
        #[serde(default)]
        strict: bool,
    },
    UpdateExports {
        operation_id: String,
        expected_original: String,
        candidate: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NfsMount {
    pub source: String,
    pub target: String,
    pub share_uuid: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub allow_existing_contents: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NfsAlias {
    pub path: String,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NfsAdminReply {
    pub ok: bool,
    pub service_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl NfsAdminReply {
    pub fn success(service_version: impl Into<String>) -> Self {
        Self {
            ok: true,
            service_version: service_version.into(),
            error: None,
        }
    }

    pub fn failure(service_version: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            ok: false,
            service_version: service_version.into(),
            error: Some(error.into()),
        }
    }
}

impl NfsAdminRequest {
    pub fn validate(&self, peer_uid: u32) -> Result<(), String> {
        if peer_uid == 0 {
            return Err("NFS admin requests require a non-root cluster account".into());
        }
        match &self.operation {
            NfsAdminOperation::Ping => Ok(()),
            NfsAdminOperation::Mount { mounts } => {
                validate_batch_size(mounts.len())?;
                for mount in mounts {
                    mount.validate()?;
                }
                Ok(())
            }
            NfsAdminOperation::Unmount {
                mounts, aliases, ..
            } => {
                validate_batch_size(mounts.len().saturating_add(aliases.len()))?;
                for mount in mounts {
                    mount.validate()?;
                }
                for alias in aliases {
                    validate_path(&alias.path, "source alias")?;
                    validate_path(&alias.target, "alias target")?;
                    if alias.path == alias.target {
                        return Err("source alias and target must be different paths".into());
                    }
                }
                Ok(())
            }
            NfsAdminOperation::RemoveMarker {
                source_root,
                share_uuid,
            } => {
                validate_path(source_root, "share marker root")?;
                Id128::parse(share_uuid)
                    .map_err(|_| "NFS share marker UUID is invalid".to_owned())?;
                Ok(())
            }
            NfsAdminOperation::CheckMarker {
                source_root,
                share_uuid,
            } => {
                validate_path(source_root, "share marker root")?;
                Id128::parse(share_uuid)
                    .map_err(|_| "NFS share marker UUID is invalid".to_owned())?;
                Ok(())
            }
            NfsAdminOperation::CheckAlias { path, target, .. } => {
                validate_path(path, "share alias")?;
                validate_path(target, "share alias target")?;
                if path == target {
                    return Err("share alias and target must be different paths".into());
                }
                Ok(())
            }
            NfsAdminOperation::UpdateExports {
                operation_id,
                expected_original,
                candidate,
            } => {
                Id128::parse(operation_id)
                    .map_err(|_| "NFS export operation ID is invalid".to_owned())?;
                validate_export_transition(expected_original, candidate)
            }
        }
    }
}

impl NfsMount {
    fn validate(&self) -> Result<(), String> {
        let (host, root) = self
            .source
            .split_once(':')
            .ok_or_else(|| "NFS source must have the form host:/absolute/path".to_owned())?;
        if !valid_host(host) {
            return Err("NFS source host is invalid".into());
        }
        validate_path(root, "NFS export path")?;
        validate_path(&self.target, "NFS mount path")?;
        if self.allow_existing_contents && root != self.target {
            return Err(
                "existing mount contents may only be overlaid when export and mount paths match"
                    .into(),
            );
        }
        Id128::parse(&self.share_uuid).map_err(|_| "NFS share UUID is invalid".to_owned())?;
        if let Some(alias) = &self.alias {
            validate_path(alias, "source alias")?;
            if alias == &self.target {
                return Err("source alias and mount path must be different paths".into());
            }
        }
        Ok(())
    }
}

fn validate_batch_size(len: usize) -> Result<(), String> {
    if len == 0 || len > MAX_BATCH_ITEMS {
        return Err(format!(
            "NFS admin batch must contain 1 to {MAX_BATCH_ITEMS} items"
        ));
    }
    Ok(())
}

fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label.as_bytes()[0] != b'-'
                && label.as_bytes()[label.len() - 1] != b'-'
        })
}

fn validate_path(path: &str, label: &str) -> Result<(), String> {
    let parsed = Path::new(path);
    if !parsed.is_absolute()
        || path == "/"
        || path.ends_with('/')
        || parsed.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || path.contains("//")
    {
        return Err(format!("{label} must be a normalized absolute path"));
    }
    Ok(())
}

/// Verify that a planned `/etc/exports` edit changes only valid macluster-managed entries.
pub fn validate_export_transition(original: &str, candidate: &str) -> Result<(), String> {
    if original.len() > MAX_NFS_ADMIN_REQUEST_BYTES || candidate.len() > MAX_NFS_ADMIN_REQUEST_BYTES
    {
        return Err("NFS exports request exceeds the 1 MiB limit".into());
    }
    if original.contains(['\0', '\r']) || candidate.contains(['\0', '\r']) {
        return Err("NFS exports request contains an invalid control character".into());
    }
    let before = export_partition(original)?;
    let after = export_partition(candidate)?;
    if before.unmanaged != after.unmanaged {
        return Err("managed NFS update attempted to change unmanaged /etc/exports entries".into());
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct ExportPartition {
    unmanaged: Vec<String>,
    managed: BTreeSet<(String, String)>,
}

fn export_partition(contents: &str) -> Result<ExportPartition, String> {
    let lines: Vec<_> = contents.lines().collect();
    let mut unmanaged = Vec::new();
    let mut managed = BTreeSet::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.starts_with("# macluster-managed ") {
            let marker: Vec<_> = line.split_whitespace().collect();
            if marker.len() != 4 {
                return Err("malformed macluster export marker".into());
            }
            Id128::parse(marker[2]).map_err(|_| "malformed macluster export UUID".to_owned())?;
            if !valid_node_id(marker[3]) {
                return Err("malformed macluster export node ID".into());
            }
            let entry = lines
                .get(index + 1)
                .ok_or_else(|| "macluster export marker has no matching export".to_owned())?;
            let fields: Vec<_> = entry.split_whitespace().collect();
            if fields.len() != 2
                || validate_path(fields[0], "managed NFS export path").is_err()
                || fields[1].parse::<std::net::Ipv4Addr>().is_err()
            {
                return Err("malformed macluster managed export entry".into());
            }
            if !managed.insert((line.to_owned(), (*entry).to_owned())) {
                return Err("duplicate macluster managed export entry".into());
            }
            index += 2;
        } else {
            unmanaged.push(line.to_owned());
            index += 1;
        }
    }
    Ok(ExportPartition { unmanaged, managed })
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{NfsAdminOperation, NfsAdminRequest, NfsMount, validate_export_transition};

    #[test]
    fn typed_mount_request_round_trips_and_validates() {
        let request = NfsAdminRequest {
            operation: NfsAdminOperation::Mount {
                mounts: vec![NfsMount {
                    source: "192.0.2.1:/Users/Shared/macluster".into(),
                    target: "/Users/Shared/macluster".into(),
                    share_uuid: "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41".into(),
                    alias: None,
                    allow_existing_contents: false,
                }],
            },
        };

        request.validate(501).unwrap();
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: NfsAdminRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn mount_request_rejects_traversal_and_invalid_uuid() {
        for (target, uuid) in [
            (
                "/Users/Shared/../private",
                "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41",
            ),
            ("/Users/Shared/data", "not-a-uuid"),
            (
                "/Users/Shared/data/",
                "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41",
            ),
        ] {
            let request = NfsAdminRequest {
                operation: NfsAdminOperation::Mount {
                    mounts: vec![NfsMount {
                        source: "192.0.2.1:/Users/Shared/data".into(),
                        target: target.into(),
                        share_uuid: uuid.into(),
                        alias: None,
                        allow_existing_contents: false,
                    }],
                },
            };
            assert!(request.validate(501).is_err());
        }
    }

    #[test]
    fn overlay_mount_requires_export_path_to_match_mount_path() {
        let request = |source: &str, target: &str| NfsAdminRequest {
            operation: NfsAdminOperation::Mount {
                mounts: vec![NfsMount {
                    source: source.into(),
                    target: target.into(),
                    share_uuid: "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41".into(),
                    alias: None,
                    allow_existing_contents: true,
                }],
            },
        };

        assert!(
            request("192.0.2.1:/opt/homebrew", "/opt/homebrew")
                .validate(501)
                .is_ok()
        );
        assert!(
            request("192.0.2.1:/opt/homebrew", "/Users/Shared/homebrew")
                .validate(501)
                .is_err()
        );
    }

    #[test]
    fn export_transition_allows_only_well_formed_managed_entry_changes() {
        let original = "/Users/Shared/other -maproot 501:20\n";
        let candidate = concat!(
            "/Users/Shared/other -maproot 501:20\n",
            "# macluster-managed d7add7d9-272f-4dc0-93cd-c62c4cdd0f41 node-001\n",
            "/Users/Shared/macluster 192.0.2.3\n",
        );

        validate_export_transition(original, candidate).unwrap();
        validate_export_transition(candidate, original).unwrap();
        assert!(
            validate_export_transition(
                original,
                "/Users/Shared/other\n/Users/private 192.0.2.3\n",
            )
            .is_err()
        );
    }

    #[test]
    fn nfs_admin_requests_reject_root_peer_and_invalid_client_source() {
        let mut request = valid_mount_request();
        assert!(request.validate(0).is_err());
        if let NfsAdminOperation::Mount { mounts } = &mut request.operation {
            mounts[0].source = "192.0.2.1:/Users/Shared/data;touch".into();
        }
        assert!(request.validate(501).is_err());
    }

    #[test]
    fn export_update_request_requires_a_valid_operation_id() {
        let request = NfsAdminRequest {
            operation: NfsAdminOperation::UpdateExports {
                expected_original: String::new(),
                candidate: String::new(),
                operation_id: "../../etc/exports".into(),
            },
        };
        assert!(request.validate(501).is_err());
    }

    #[test]
    fn marker_operations_are_limited_to_normalized_roots_and_uuid_identity() {
        let valid = NfsAdminRequest {
            operation: NfsAdminOperation::RemoveMarker {
                source_root: "/Users/Shared/macluster".into(),
                share_uuid: "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41".into(),
            },
        };
        valid.validate(501).unwrap();

        for source_root in ["/Users/Shared/../private", "/Users/Shared/data/"] {
            let request = NfsAdminRequest {
                operation: NfsAdminOperation::RemoveMarker {
                    source_root: source_root.into(),
                    share_uuid: "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41".into(),
                },
            };
            assert!(request.validate(501).is_err());
        }

        let alias = NfsAdminRequest {
            operation: NfsAdminOperation::CheckAlias {
                path: "/Users/Shared/tools".into(),
                target: "/Users/Shared/tools-source".into(),
                strict: true,
            },
        };
        alias.validate(501).unwrap();
        let invalid_alias = NfsAdminRequest {
            operation: NfsAdminOperation::CheckAlias {
                path: "/Users/Shared/../private".into(),
                target: "/Users/Shared/tools-source".into(),
                strict: true,
            },
        };
        assert!(invalid_alias.validate(501).is_err());
    }

    fn valid_mount_request() -> NfsAdminRequest {
        NfsAdminRequest {
            operation: NfsAdminOperation::Mount {
                mounts: vec![NfsMount {
                    source: "192.0.2.1:/Users/Shared/macluster".into(),
                    target: "/Users/Shared/macluster".into(),
                    share_uuid: "d7add7d9-272f-4dc0-93cd-c62c4cdd0f41".into(),
                    alias: None,
                    allow_existing_contents: false,
                }],
            },
        }
    }
}
