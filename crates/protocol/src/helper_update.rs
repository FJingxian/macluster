use std::{collections::BTreeSet, path::Path};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::identifiers::Id128;

pub const MAX_HELPER_UPDATE_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_HELPER_ARTIFACTS: usize = 256;
const MAX_REVISION_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HelperUpdateManifest {
    pub format_version: u16,
    pub cluster_id: String,
    pub sequence: u64,
    pub architecture: String,
    pub artifacts: Vec<HelperArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct HelperArtifact {
    pub component: HelperComponent,
    pub revision: String,
    pub sha256: String,
    /// A single safe basename under the private stage directory. Identical
    /// payloads may share this name to avoid retransmitting the same CLI for
    /// multiple managed NFS recovery targets.
    pub stage_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelperComponent {
    PowerSampler,
    NfsAdminCli,
    NfsRecovery { target: String, share_uuid: String },
}

pub fn verify_manifest(
    expected_cluster_id: &str,
    public_key: &[u8; 32],
    manifest_bytes: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<HelperUpdateManifest, String> {
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_HELPER_UPDATE_MANIFEST_BYTES {
        return Err(format!(
            "helper update manifest must contain 1 to {MAX_HELPER_UPDATE_MANIFEST_BYTES} bytes"
        ));
    }
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("invalid cluster update public key: {error}"))?;
    let signature = Signature::from_bytes(signature_bytes);
    key.verify_strict(manifest_bytes, &signature)
        .map_err(|_| "helper update manifest signature is invalid".to_owned())?;
    let manifest: HelperUpdateManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("invalid helper update manifest: {error}"))?;
    manifest.validate()?;
    if manifest.cluster_id != expected_cluster_id {
        return Err("helper update manifest belongs to a different cluster".into());
    }
    Ok(manifest)
}

impl HelperUpdateManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != 1 {
            return Err(format!(
                "unsupported helper update manifest version {}",
                self.format_version
            ));
        }
        let cluster_id = Id128::parse(&self.cluster_id)
            .map_err(|_| "helper update cluster ID is invalid".to_owned())?;
        if cluster_id.to_string() != self.cluster_id {
            return Err("helper update cluster ID must be canonical".into());
        }
        if self.sequence == 0 {
            return Err("helper update sequence must be greater than zero".into());
        }
        if !matches!(self.architecture.as_str(), "arm64" | "x86_64") {
            return Err("helper update architecture must be arm64 or x86_64".into());
        }
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_HELPER_ARTIFACTS {
            return Err(format!(
                "helper update must contain 1 to {MAX_HELPER_ARTIFACTS} artifacts"
            ));
        }
        let mut seen = BTreeSet::new();
        let mut stage_digests = std::collections::BTreeMap::new();
        for artifact in &self.artifacts {
            if !valid_revision(&artifact.revision) {
                return Err("helper artifact revision is invalid".into());
            }
            if !valid_sha256(&artifact.sha256) {
                return Err("helper artifact SHA-256 digest is invalid".into());
            }
            if !valid_stage_name(&artifact.stage_name) {
                return Err("helper artifact stage name is invalid".into());
            }
            if !valid_component(&artifact.component) {
                return Err("helper artifact component identity is invalid".into());
            }
            if !seen.insert(artifact.component.clone()) {
                return Err("helper update manifest contains a duplicate component".into());
            }
            if stage_digests
                .insert(&artifact.stage_name, &artifact.sha256)
                .is_some_and(|previous| previous != &artifact.sha256)
            {
                return Err("helper artifacts sharing a stage name must share a digest".into());
            }
        }
        Ok(())
    }
}

fn valid_revision(revision: &str) -> bool {
    !revision.is_empty()
        && revision.len() <= MAX_REVISION_BYTES
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_stage_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 96
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_component(component: &HelperComponent) -> bool {
    match component {
        HelperComponent::PowerSampler | HelperComponent::NfsAdminCli => true,
        HelperComponent::NfsRecovery { target, share_uuid } => {
            valid_absolute_path(target)
                && Id128::parse(share_uuid).is_ok_and(|uuid| uuid.to_string() == *share_uuid)
        }
    }
}

fn valid_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && path != Path::new("/")
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains(['\0', '\n', '\r'])
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::{HelperArtifact, HelperComponent, HelperUpdateManifest, verify_manifest};

    const CLUSTER_ID: &str = "00000000-0000-4000-8000-000000000001";

    fn manifest() -> HelperUpdateManifest {
        HelperUpdateManifest {
            format_version: 1,
            cluster_id: CLUSTER_ID.into(),
            sequence: 1,
            architecture: "arm64".into(),
            artifacts: vec![HelperArtifact {
                component: HelperComponent::PowerSampler,
                revision: "power-7".into(),
                sha256: "a".repeat(64),
                stage_name: "power.bin".into(),
            }],
        }
    }

    fn encoded_and_signed(value: &HelperUpdateManifest) -> (Vec<u8>, [u8; 64], [u8; 32]) {
        let bytes = serde_json::to_vec(value).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        (
            bytes.clone(),
            key.sign(&bytes).to_bytes(),
            key.verifying_key().to_bytes(),
        )
    }

    #[test]
    fn verifies_the_exact_signed_manifest() {
        let value = manifest();
        let (bytes, signature, public) = encoded_and_signed(&value);
        assert_eq!(
            verify_manifest(CLUSTER_ID, &public, &bytes, &signature).unwrap(),
            value
        );
    }

    #[test]
    fn rejects_tampering_wrong_cluster_sequence_and_architecture() {
        let value = manifest();
        let (bytes, signature, public) = encoded_and_signed(&value);
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(verify_manifest(CLUSTER_ID, &public, &tampered, &signature).is_err());

        for invalid in [
            HelperUpdateManifest {
                cluster_id: "00000000-0000-4000-8000-000000000002".into(),
                ..value.clone()
            },
            HelperUpdateManifest {
                sequence: 0,
                ..value.clone()
            },
            HelperUpdateManifest {
                architecture: "ppc".into(),
                ..value.clone()
            },
        ] {
            let (bytes, signature, public) = encoded_and_signed(&invalid);
            assert!(verify_manifest(CLUSTER_ID, &public, &bytes, &signature).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_and_malformed_components() {
        let mut duplicate = manifest();
        duplicate.artifacts.push(duplicate.artifacts[0].clone());
        let (bytes, signature, public) = encoded_and_signed(&duplicate);
        assert!(verify_manifest(CLUSTER_ID, &public, &bytes, &signature).is_err());

        let mut bad_digest = manifest();
        bad_digest.artifacts[0].sha256 = "xyz".into();
        let (bytes, signature, public) = encoded_and_signed(&bad_digest);
        assert!(verify_manifest(CLUSTER_ID, &public, &bytes, &signature).is_err());

        let mut bad_path = manifest();
        bad_path.artifacts[0].component = HelperComponent::NfsRecovery {
            target: "/Volumes/../private".into(),
            share_uuid: CLUSTER_ID.into(),
        };
        let (bytes, signature, public) = encoded_and_signed(&bad_path);
        assert!(verify_manifest(CLUSTER_ID, &public, &bytes, &signature).is_err());
    }

    #[test]
    fn rejects_unknown_component_names() {
        let bytes = format!(
            r#"{{"format_version":1,"cluster_id":"{CLUSTER_ID}","sequence":1,"architecture":"arm64","artifacts":[{{"component":{{"kind":"root_shell"}},"revision":"r1","sha256":"{}"}}]}}"#,
            "a".repeat(64)
        )
        .into_bytes();
        let key = SigningKey::from_bytes(&[9; 32]);
        let signature = key.sign(&bytes).to_bytes();
        assert!(
            verify_manifest(
                CLUSTER_ID,
                &key.verifying_key().to_bytes(),
                &bytes,
                &signature
            )
            .is_err()
        );
    }
}
