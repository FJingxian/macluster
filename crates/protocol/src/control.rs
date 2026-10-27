//! Versioned control messages for the local CLI-to-controller IPC channel.

use serde::{Deserialize, Serialize};

use crate::{identifiers::RequestId, types::ControllerEpoch};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub binding_digest: String,
    pub namespace: String,
    pub uid: u32,
    pub build_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerLifecycle {
    Ready,
    Paused,
    RecoveryPending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControllerHello {
    pub protocol_version: u16,
    pub binding_digest: String,
    pub namespace: String,
    pub uid: u32,
    pub build_id: String,
    pub capabilities: Vec<String>,
    pub controller_epoch: ControllerEpoch,
    pub config_generation: u64,
    pub lifecycle: ControllerLifecycle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    WrongPeer,
    WrongCluster,
    IncompatibleProtocol,
    Busy,
    StaleGeneration,
    Maintenance,
    Unavailable,
    Conflict,
    InvalidRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlError {
    pub code: ControlErrorCode,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum HelloResponse {
    Accepted(ControllerHello),
    Rejected(ControlError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "payload", content = "value", rename_all = "snake_case")]
pub enum ControlPayload {
    Status(ControllerHello),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlRequest {
    pub request_id: RequestId,
    #[serde(default)]
    pub expected_generation: Option<u64>,
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlResponse {
    pub request_id: RequestId,
    pub result: Result<ControlPayload, ControlError>,
}
