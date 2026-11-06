use super::{AppResult, addresses, addresses::InterfaceAddress};
use macluster_core::config::{ClusterConfig, Transport};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_SCAN_ADDRESSES: usize = 1_024;
const MAX_SCAN_WORKERS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(180);
const SSH_BANNER_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_SSH_BANNER_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortState {
    Open,
    Closed,
    NoResponse,
}

impl PortState {
    fn label(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Closed => "CLOSED",
            Self::NoResponse => "NO RESPONSE",
        }
    }
}

#[derive(Clone, Debug)]
struct HostProbe {
    ip: Ipv4Addr,
    ssh: PortState,
    banner: Option<String>,
    rdp: bool,
    afp: bool,
    ard: bool,
}

impl HostProbe {
    fn has_service(&self) -> bool {
        self.ssh == PortState::Open || self.rdp || self.afp || self.ard
    }

    fn services(&self) -> String {
        [(self.rdp, "RDP"), (self.afp, "AFP"), (self.ard, "ARD")]
            .into_iter()
            .filter_map(|(open, name)| open.then_some(name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScanRow {
    ip: String,
    mac: String,
    state: String,
    ssh: String,
    services: String,
    node: String,
    os: String,
}

fn configured_login_address(config: &ClusterConfig) -> AppResult<Ipv4Addr> {
    let (id, node) = if let Some(login_id) = config.login_node.as_ref() {
        let id = login_id.as_str();
        let node = config.nodes.get(id).ok_or_else(|| {
            (
                1,
                format!("configured login node '{id}' is missing from the cluster config"),
            )
        })?;
        (id, node)
    } else {
        config
            .nodes
            .iter()
            .find(|(_, node)| node.transport == Transport::Local)
            .map(|(id, node)| (id.as_str(), node))
            .ok_or_else(|| {
                (
                    1,
                    "cannot identify the local login node in the cluster config".into(),
                )
            })?
    };
    if node.transport != Transport::Local {
        return Err((
            1,
            format!("run `mnode --scan` on the configured login Mac ({id})"),
        ));
    }
    node.host.parse::<Ipv4Addr>().map_err(|_| {
        (
            1,
            format!("configured login address '{}' is not IPv4", node.host),
        )
    })
}

fn select_interface<'a>(
    login_address: Ipv4Addr,
    interfaces: &'a [InterfaceAddress],
) -> AppResult<&'a InterfaceAddress> {
    interfaces
        .iter()
        .find(|interface| interface.address == login_address)
        .ok_or_else(|| {
            (
                1,
                format!(
                    "configured login address {login_address} is not assigned to an active local IPv4 interface; reconnect the cluster interface or update the cluster address"
                ),
            )
        })
}

fn subnet_cidr(interface: &InterfaceAddress) -> String {
    let network = Ipv4Addr::from(u32::from(interface.address) & interface.mask);
    format!("{network}/{}", interface.mask.count_ones())
}

fn candidate_addresses(
    interface: &InterfaceAddress,
    local_addresses: &[Ipv4Addr],
) -> AppResult<Vec<Ipv4Addr>> {
    let host_mask = !interface.mask;
    let total_addresses = u64::from(host_mask) + 1;
    let (first_offset, end_offset) = match total_addresses {
        1 => (0, 0),
        // RFC 3021 point-to-point links use both /31 addresses as hosts.
        2 => (0, 2),
        _ => (1, total_addresses - 1),
    };
    let local = local_addresses.iter().copied().collect::<BTreeSet<_>>();
    let network_base = u32::from(interface.address) & interface.mask;
    let local_in_range = (first_offset..end_offset)
        .filter(|offset| local.contains(&Ipv4Addr::from(network_base + *offset as u32)))
        .count();
    let candidate_count = (end_offset - first_offset) as usize - local_in_range;
    if candidate_count > MAX_SCAN_ADDRESSES {
        return Err((
            1,
            format!(
                "login subnet {} has {candidate_count} candidate addresses; `mnode --scan` is limited to {MAX_SCAN_ADDRESSES} addresses",
                subnet_cidr(interface)
            ),
        ));
    }

    Ok((first_offset..end_offset)
        .map(|offset| Ipv4Addr::from(network_base + offset as u32))
        .filter(|address| !local.contains(address))
        .collect())
}

fn connect(address: Ipv4Addr, port: u16) -> Result<TcpStream, PortState> {
    TcpStream::connect_timeout(&SocketAddr::from((address, port)), CONNECT_TIMEOUT).map_err(
        |error| match error.kind() {
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                PortState::Closed
            }
            _ => PortState::NoResponse,
        },
    )
}

fn read_ssh_banner(stream: &mut TcpStream) -> Option<String> {
    let deadline = Instant::now() + SSH_BANNER_TIMEOUT;
    let mut bytes = Vec::with_capacity(MAX_SSH_BANNER_BYTES);
    let mut buffer = [0_u8; 64];
    while bytes.len() < MAX_SSH_BANNER_BYTES {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        let available = (MAX_SSH_BANNER_BYTES - bytes.len()).min(buffer.len());
        match stream.read(&mut buffer[..available]) {
            Ok(0) => break,
            Ok(read) => {
                if let Some(line_end) = buffer[..read].iter().position(|byte| *byte == b'\n') {
                    bytes.extend_from_slice(&buffer[..line_end]);
                    break;
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(_) => break,
        }
    }
    let banner = String::from_utf8_lossy(&bytes)
        .trim_matches(['\r', '\n'])
        .trim()
        .to_owned();
    (!banner.is_empty()).then_some(banner)
}

fn probe_ssh(address: Ipv4Addr) -> (PortState, Option<String>) {
    match connect(address, 22) {
        Ok(mut stream) => (PortState::Open, read_ssh_banner(&mut stream)),
        Err(state) => (state, None),
    }
}

fn probe_port(address: Ipv4Addr, port: u16) -> bool {
    connect(address, port).is_ok()
}

fn probe_host(ip: Ipv4Addr) -> HostProbe {
    let (ssh, banner) = probe_ssh(ip);
    HostProbe {
        ip,
        ssh,
        banner,
        rdp: probe_port(ip, 3389),
        afp: probe_port(ip, 548),
        ard: probe_port(ip, 3283),
    }
}

fn parse_ifconfig_link_rate(text: &str) -> Option<String> {
    let media = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("media:"))?;
    let selected = media.split_once('(').map_or(media, |(_, selected)| {
        selected.split(')').next().unwrap_or("")
    });
    for token in selected.split_whitespace() {
        let Some((prefix, _)) = token.split_once("base") else {
            continue;
        };
        let unit = prefix
            .chars()
            .last()
            .filter(|value| value.is_ascii_alphabetic());
        let numeric = unit.map_or(prefix, |unit| &prefix[..prefix.len() - unit.len_utf8()]);
        let value = numeric.parse::<f64>().ok()?;
        if value <= 0.0 {
            continue;
        }
        let megabits = if unit.is_some_and(|unit| unit.eq_ignore_ascii_case(&'G')) {
            value * 1_000.0
        } else {
            value
        };
        let (value, unit) = if megabits >= 1_000.0 {
            (megabits / 1_000.0, "Gb/s")
        } else {
            (megabits, "Mb/s")
        };
        return Some(if value.fract() == 0.0 {
            format!("{value:.0} {unit}")
        } else {
            format!("{value:.1} {unit}")
        });
    }
    None
}

fn parse_thunderbolt_link_rate(profile: &serde_json::Value, interface: &str) -> Option<String> {
    let is_thunderbolt_bridge = profile
        .get("SPNetworkDataType")?
        .as_array()?
        .iter()
        .any(|entry| {
            entry.get("interface").and_then(serde_json::Value::as_str) == Some(interface)
                && entry
                    .get("_name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case("Thunderbolt Bridge"))
        });
    if !is_thunderbolt_bridge {
        return None;
    }

    let mut rates = BTreeSet::new();
    for bus in profile.get("SPThunderboltDataType")?.as_array()? {
        let Some(bus) = bus.as_object() else {
            continue;
        };
        for (key, port) in bus {
            if !key.starts_with("receptacle_") || !key.ends_with("_tag") {
                continue;
            }
            let Some(port) = port.as_object() else {
                continue;
            };
            if port
                .get("receptacle_status_key")
                .and_then(serde_json::Value::as_str)
                != Some("receptacle_connected")
            {
                continue;
            }
            let Some(speed) = port
                .get("current_speed_key")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|speed| !speed.is_empty() && !speed.starts_with("Up to "))
            else {
                continue;
            };
            rates.insert(speed.to_owned());
        }
    }
    (!rates.is_empty()).then(|| rates.into_iter().collect::<Vec<_>>().join(", "))
}

fn interface_link_rate(interface: &str) -> Option<String> {
    let output = Command::new("/sbin/ifconfig")
        .arg(interface)
        .output()
        .ok()?;
    if output.status.success()
        && let Some(rate) = parse_ifconfig_link_rate(&String::from_utf8_lossy(&output.stdout))
    {
        return Some(rate);
    }
    if !interface.starts_with("bridge") {
        return None;
    }

    let output = Command::new("/usr/sbin/system_profiler")
        .args(["-json", "SPNetworkDataType", "SPThunderboltDataType"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let profile = serde_json::from_slice(&output.stdout).ok()?;
    parse_thunderbolt_link_rate(&profile, interface).map(|rate| format!("{rate} (Thunderbolt)"))
}

fn scan_worker_count(address_count: usize) -> usize {
    address_count.min(MAX_SCAN_WORKERS)
}

fn scan_addresses(addresses: &[Ipv4Addr]) -> Vec<HostProbe> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(addresses.len()));
    thread::scope(|scope| {
        let handles = (0..scan_worker_count(addresses.len()))
            .map(|_| {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(ip) = addresses.get(index).copied() else {
                            break;
                        };
                        let probe = probe_host(ip);
                        if let Ok(mut results) = results.lock() {
                            results.push(probe);
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            let _ = handle.join();
        }
    });
    let mut results = results.into_inner().unwrap_or_default();
    results.sort_by_key(|probe| u32::from(probe.ip));
    results
}

fn os_guess(banner: Option<&str>, rdp: bool, afp: bool, ard: bool) -> &'static str {
    let banner = banner.unwrap_or_default().to_ascii_lowercase();
    if rdp || banner.contains("openssh_for_windows") {
        "Windows?"
    } else if [
        "ubuntu", "debian", "alpine", "rhel", "centos", "fedora", "suse", "linux",
    ]
    .iter()
    .any(|identifier| banner.contains(identifier))
    {
        "Linux?"
    } else if afp
        || ard
        || ["apple", "darwin", "macos"]
            .iter()
            .any(|identifier| banner.contains(identifier))
    {
        "macOS?"
    } else {
        "Unknown"
    }
}

fn row_for(
    ip: Ipv4Addr,
    probe: Option<&HostProbe>,
    mac: Option<&String>,
    registered_nodes: &[String],
    is_local: bool,
) -> ScanRow {
    let ssh = if is_local {
        "LOCAL"
    } else {
        probe.map_or("NO RESPONSE", |probe| probe.ssh.label())
    };
    let services = probe.map_or_else(String::new, HostProbe::services);
    let has_service = probe.is_some_and(HostProbe::has_service);
    let state = if is_local {
        "LOGIN NODE"
    } else if !registered_nodes.is_empty() {
        "REGISTERED"
    } else if probe.is_some_and(|probe| probe.ssh == PortState::Open) {
        "SSH OPEN"
    } else if has_service {
        "SERVICE OPEN"
    } else {
        "LAN NEIGHBOR"
    };
    let os = if is_local {
        "macOS"
    } else {
        os_guess(
            probe.and_then(|probe| probe.banner.as_deref()),
            probe.is_some_and(|probe| probe.rdp),
            probe.is_some_and(|probe| probe.afp),
            probe.is_some_and(|probe| probe.ard),
        )
    };
    ScanRow {
        ip: ip.to_string(),
        mac: mac.map_or_else(|| "-".into(), Clone::clone),
        state: state.into(),
        ssh: ssh.into(),
        services: if services.is_empty() {
            "-".into()
        } else {
            services
        },
        node: if registered_nodes.is_empty() {
            "-".into()
        } else {
            registered_nodes.join(",")
        },
        os: os.into(),
    }
}

fn format_scan_results(
    subnet: &str,
    interface: &str,
    link_rate: Option<&str>,
    rows: &[ScanRow],
) -> String {
    let headers = ["IP", "MAC", "STATE", "SSH", "SERVICES", "NODE", "OS GUESS"];
    let widths = std::array::from_fn::<_, 7, _>(|index| {
        rows.iter()
            .map(|row| {
                [
                    row.ip.as_str(),
                    row.mac.as_str(),
                    row.state.as_str(),
                    row.ssh.as_str(),
                    row.services.as_str(),
                    row.node.as_str(),
                    row.os.as_str(),
                ][index]
                    .chars()
                    .count()
            })
            .max()
            .unwrap_or(0)
            .max(headers[index].len())
    });
    let line = |cells: [&str; 7]| {
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| format!("{cell:<width$}", width = widths[index]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut output = format!(
        "Login subnet {subnet} on {interface} (interface link rate: {})\n",
        link_rate.unwrap_or("N/A")
    );
    output.push_str(&line(headers));
    output.push('\n');
    for row in rows {
        output.push_str(&line([
            &row.ip,
            &row.mac,
            &row.state,
            &row.ssh,
            &row.services,
            &row.node,
            &row.os,
        ]));
        output.push('\n');
    }
    if !rows.iter().any(|row| row.state != "LOGIN NODE") {
        output.push_str("No other cluster candidates were found.\n");
    }
    output.push_str("Add a candidate with `mnode -a USER@IP`; SSH host fingerprint verification still applies.\n");
    output
}

fn registered_nodes_in_subnet(
    config: &ClusterConfig,
    interface: &InterfaceAddress,
) -> BTreeMap<Ipv4Addr, Vec<String>> {
    let mut registered = BTreeMap::<Ipv4Addr, Vec<String>>::new();
    for (id, node) in &config.nodes {
        let Ok(ip) = node.host.parse::<Ipv4Addr>() else {
            continue;
        };
        if interface.contains(ip) {
            registered.entry(ip).or_default().push(id.clone());
        }
    }
    registered
}

pub(super) fn scan_nodes(config: &ClusterConfig) -> AppResult<()> {
    let login_address = configured_login_address(config)?;
    let interfaces = addresses::local_interfaces()?;
    let interface = select_interface(login_address, &interfaces)?;
    let local_addresses = interfaces
        .iter()
        .map(|interface| interface.address)
        .collect::<Vec<_>>();
    let candidates = candidate_addresses(interface, &local_addresses)?;
    let subnet = subnet_cidr(interface);
    println!(
        "Scanning {subnet} on {} ({} addresses; SSH/RDP/Apple service probes)...",
        interface.interface,
        candidates.len()
    );
    let link_rate = interface_link_rate(&interface.interface);

    let probes = scan_addresses(&candidates);
    let probes = probes
        .into_iter()
        .map(|probe| (probe.ip, probe))
        .collect::<BTreeMap<_, _>>();
    let neighbors = addresses::neighbors()
        .into_iter()
        .filter(|(ip, _)| interface.contains(*ip))
        .collect::<BTreeMap<_, _>>();
    let registered = registered_nodes_in_subnet(config, interface);
    let mut result_ips = probes
        .values()
        .filter(|probe| probe.has_service())
        .map(|probe| probe.ip)
        .chain(neighbors.keys().copied())
        .chain(registered.keys().copied())
        .collect::<BTreeSet<_>>();
    result_ips.insert(login_address);

    let rows = result_ips
        .into_iter()
        .map(|ip| {
            let mac = neighbors.get(&ip).or_else(|| {
                if ip == login_address {
                    interface.mac.as_ref()
                } else {
                    None
                }
            });
            row_for(
                ip,
                probes.get(&ip),
                mac,
                registered.get(&ip).map_or(&[], Vec::as_slice),
                ip == login_address,
            )
        })
        .collect::<Vec<_>>();
    print!(
        "{}",
        format_scan_results(&subnet, &interface.interface, link_rate.as_deref(), &rows)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        InterfaceAddress, PortState, ScanRow, candidate_addresses, format_scan_results, os_guess,
        parse_ifconfig_link_rate, parse_thunderbolt_link_rate, scan_worker_count, select_interface,
    };
    use serde_json::json;
    use std::net::Ipv4Addr;

    fn interface(address: &str, mask: &str, name: &str) -> InterfaceAddress {
        InterfaceAddress {
            interface: name.into(),
            address: address.parse().unwrap(),
            mask: u32::from(mask.parse::<Ipv4Addr>().unwrap()),
            mac: None,
        }
    }

    #[test]
    fn scan_selects_the_exact_configured_login_interface() {
        let interfaces = [
            interface("198.51.100.2", "255.255.255.0", "en0"),
            interface("192.0.2.2", "255.255.255.0", "bridge0"),
        ];
        let selected = select_interface("192.0.2.2".parse().unwrap(), &interfaces).unwrap();
        assert_eq!(selected.interface, "bridge0");
    }

    #[test]
    fn scan_fails_when_configured_login_address_is_not_local() {
        let interfaces = [interface("198.51.100.2", "255.255.255.0", "en0")];
        let error = select_interface("192.0.2.2".parse().unwrap(), &interfaces).unwrap_err();
        assert!(error.1.contains("192.0.2.2"));
        assert!(error.1.contains("active local IPv4 interface"));
    }

    #[test]
    fn scan_candidate_addresses_exclude_network_broadcast_and_all_local_ips() {
        let interface = interface("192.0.2.2", "255.255.255.0", "bridge0");
        let candidates = candidate_addresses(&interface, &["192.0.2.2".parse().unwrap()]).unwrap();
        assert_eq!(candidates.len(), 253);
        assert!(candidates.contains(&"192.0.2.1".parse().unwrap()));
        assert!(candidates.contains(&"192.0.2.254".parse().unwrap()));
        assert!(!candidates.contains(&"192.0.2.0".parse().unwrap()));
        assert!(!candidates.contains(&"192.0.2.255".parse().unwrap()));
        assert!(!candidates.contains(&"192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn scan_candidate_addresses_support_point_to_point_and_host_routes() {
        let point_to_point = interface("192.0.2.0", "255.255.255.254", "bridge0");
        assert_eq!(
            candidate_addresses(&point_to_point, &["192.0.2.0".parse().unwrap()]).unwrap(),
            ["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
        );
        let host_route = interface("192.0.2.1", "255.255.255.255", "bridge0");
        assert!(
            candidate_addresses(&host_route, &["192.0.2.1".parse().unwrap()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn scan_rejects_subnets_over_the_bounded_limit() {
        let interface = interface("198.51.100.2", "255.255.248.0", "bridge0");
        let error =
            candidate_addresses(&interface, &["198.51.100.2".parse().unwrap()]).unwrap_err();
        assert!(error.1.contains("2045 candidate addresses"));
        assert!(error.1.contains("limited to 1024 addresses"));
    }

    #[test]
    fn scan_os_guess_requires_specific_evidence() {
        assert_eq!(
            os_guess(Some("SSH-2.0-OpenSSH_for_Windows_9.5"), false, false, false),
            "Windows?"
        );
        assert_eq!(
            os_guess(Some("SSH-2.0-OpenSSH_9.2p1 Ubuntu-1"), false, false, false),
            "Linux?"
        );
        assert_eq!(os_guess(None, false, true, false), "macOS?");
        assert_eq!(
            os_guess(Some("SSH-2.0-OpenSSH_9.9"), false, false, false),
            "Unknown"
        );
    }

    #[test]
    fn scan_output_is_left_aligned_and_explains_add_command() {
        let output = format_scan_results(
            "192.0.2.0/24",
            "bridge0",
            Some("40 Gb/s (Thunderbolt)"),
            &[ScanRow {
                ip: "192.0.2.3".into(),
                mac: "00:11:22:33:44:55".into(),
                state: "SSH OPEN".into(),
                ssh: PortState::Open.label().into(),
                services: "-".into(),
                node: "-".into(),
                os: "Unknown".into(),
            }],
        );
        assert!(
            output.contains("interface link rate: 40 Gb/s (Thunderbolt)"),
            "{output}"
        );
        assert!(output.contains("IP         MAC"), "{output}");
        assert!(output.contains("192.0.2.3  00:11:22:33:44:55"), "{output}");
        assert!(output.contains("mnode -a USER@IP"), "{output}");
    }

    #[test]
    fn scan_worker_pool_is_bounded() {
        assert_eq!(scan_worker_count(0), 0);
        assert_eq!(scan_worker_count(12), 12);
        assert_eq!(scan_worker_count(300), 64);
    }

    #[test]
    fn link_rate_parser_reads_active_ethernet_media_only() {
        assert_eq!(
            parse_ifconfig_link_rate(
                "en0: flags=8863<UP>\n\tmedia: autoselect (1000baseT <full-duplex>)\n"
            )
            .as_deref(),
            Some("1 Gb/s")
        );
        assert_eq!(
            parse_ifconfig_link_rate("bridge0: flags=8a63<UP>\n\tmedia: autoselect\n"),
            None
        );
        assert_eq!(
            parse_ifconfig_link_rate("en5: flags=8963<UP>\n\tmedia: autoselect (10Gbase-T)\n")
                .as_deref(),
            Some("10 Gb/s")
        );
    }

    #[test]
    fn thunderbolt_link_rate_requires_the_scanned_thunderbolt_bridge_and_connected_port() {
        let profile = json!({
            "SPNetworkDataType": [
                { "_name": "Thunderbolt Bridge", "interface": "bridge0" },
                { "_name": "Wi-Fi", "interface": "en0" }
            ],
            "SPThunderboltDataType": [
                { "receptacle_1_tag": {
                    "receptacle_status_key": "receptacle_no_devices_connected",
                    "current_speed_key": "Up to 40 Gb/s"
                }},
                { "receptacle_1_tag": {
                    "receptacle_status_key": "receptacle_connected",
                    "current_speed_key": "40 Gb/s"
                }}
            ]
        });
        assert_eq!(
            parse_thunderbolt_link_rate(&profile, "bridge0").as_deref(),
            Some("40 Gb/s")
        );
        assert_eq!(parse_thunderbolt_link_rate(&profile, "en0"), None);
    }
}
