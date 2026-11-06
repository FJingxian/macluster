//! Shared macluster wire types and versioned message framing.

pub mod control;
pub mod framing;
pub mod helper_update;
pub mod identifiers;
pub mod types;

pub mod nfs_admin;
pub mod resources;

/// Stable identity of the source build shared by the CLI, controller, and
/// Agents across target architectures.
pub const BUILD_ID: &str = env!("MACLUSTER_BUILD_ID");
