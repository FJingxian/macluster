use std::{
    io::{self, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use macluster_protocol::types::POWER_SAMPLE_CACHE_TTL_MS;
use serde::{Deserialize, Serialize};

mod fan;
mod helper_update;
mod nfs_admin;

const POWER_SOCKET: &str = "/var/run/org.macluster.power.sock";
const POWER_CACHE_TTL: Duration = Duration::from_millis(POWER_SAMPLE_CACHE_TTL_MS);
const POWER_REFRESH_INTERVAL: Duration = Duration::from_secs(4);
const GPU_CACHE_TTL: Duration = Duration::from_secs(8);
const GPU_SAMPLE_WINDOW_MS: u32 = 100;
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct PowerSample {
    watts: Option<f64>,
    scope: Option<String>,
    available: bool,
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_window_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct PowerReading {
    watts: f64,
    scope: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct GpuReading {
    percent: f64,
    source: &'static str,
    window_ms: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct GpuSampler {
    sampler: macmon::Sampler,
    supported: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GpuSampler {
    fn new() -> Result<Self, String> {
        let sampler = macmon::Sampler::new()
            .map_err(|error| format!("could not initialize macmon GPU sampler: {error}"))?;
        let soc = sampler.get_soc_info();
        let supported = soc.gpu_cores > 0 && soc.gpu_freqs.len() > 1;
        if !supported {
            return Err("GPU utilization is not supported by this hardware".into());
        }
        Ok(Self { sampler, supported })
    }

    fn sample(
        &mut self,
    ) -> (
        Result<GpuReading, String>,
        Option<PowerReading>,
        Option<f32>,
    ) {
        let metrics = match self.sampler.get_metrics(GPU_SAMPLE_WINDOW_MS) {
            Ok(metrics) => metrics,
            Err(error) => {
                return (
                    Err(format!("macmon GPU/power sampling failed: {error}")),
                    None,
                    None,
                );
            }
        };
        (
            gpu_reading(self.supported, metrics.gpu_active_ratio).map_err(str::to_owned),
            macmon_power_reading(metrics.sys_power, metrics.all_power),
            metrics.temp.cpu_temp_avg,
        )
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
struct GpuSampler;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl GpuSampler {
    fn new() -> Result<Self, String> {
        Err("GPU utilization sampling requires Apple Silicon".into())
    }

    fn sample(
        &mut self,
    ) -> (
        Result<GpuReading, String>,
        Option<PowerReading>,
        Option<f32>,
    ) {
        (
            Err("GPU and macmon power sampling require Apple Silicon".into()),
            None,
            None,
        )
    }
}

fn macmon_power_reading(system_watts: f32, soc_watts: f32) -> Option<PowerReading> {
    if system_watts.is_finite() && system_watts > 0.0 {
        return Some(PowerReading {
            watts: f64::from(system_watts),
            scope: "System",
        });
    }
    if soc_watts.is_finite() && soc_watts > 0.0 {
        return Some(PowerReading {
            watts: f64::from(soc_watts),
            scope: "SoC",
        });
    }
    None
}

fn power_sample_from_reading(reading: PowerReading) -> PowerSample {
    PowerSample {
        watts: Some(reading.watts),
        scope: Some(reading.scope.into()),
        available: true,
        reason: None,
        age_ms: Some(0),
        gpu_percent: None,
        gpu_source: None,
        gpu_age_ms: None,
        gpu_window_ms: None,
        gpu_reason: None,
    }
}

fn gpu_reading(supported: bool, active_ratio: f32) -> Result<GpuReading, &'static str> {
    if !supported {
        return Err("GPU utilization is not supported by this hardware");
    }
    if !active_ratio.is_finite() || !(0.0..=1.0).contains(&active_ratio) {
        return Err("macmon returned an invalid GPU active residency ratio");
    }
    Ok(GpuReading {
        percent: f64::from(active_ratio) * 100.0,
        source: "macmon",
        window_ms: GPU_SAMPLE_WINDOW_MS,
    })
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[derive(Default)]
struct PowerCache {
    last_good: Option<(Instant, PowerSample)>,
    last_error: Option<String>,
    last_good_gpu: Option<(Instant, GpuReading)>,
    gpu_error: Option<String>,
    last_good_temperature: Option<(Instant, f32)>,
}

impl PowerCache {
    fn update(
        &mut self,
        sample: PowerSample,
        gpu: Result<GpuReading, String>,
        temperature: Option<f32>,
        at: Instant,
    ) {
        if sample.available
            && sample
                .watts
                .is_some_and(|watts| watts.is_finite() && watts >= 0.0)
            && sample.scope.is_some()
        {
            self.last_good = Some((at, sample));
            self.last_error = None;
        } else {
            self.last_error = sample
                .reason
                .or_else(|| Some("power sample unavailable".into()));
        }
        match gpu {
            Ok(sample) => {
                self.last_good_gpu = Some((at, sample));
                self.gpu_error = None;
            }
            Err(error) => self.gpu_error = Some(error),
        }
        if let Some(temperature) =
            temperature.filter(|value| value.is_finite() && (0.0..=150.0).contains(value))
        {
            self.last_good_temperature = Some((at, temperature));
        }
    }

    fn temperature(&self, now: Instant) -> Option<f32> {
        self.last_good_temperature
            .filter(|(sampled_at, _)| {
                now.saturating_duration_since(*sampled_at) <= Duration::from_secs(18)
            })
            .map(|(_, temperature)| temperature)
    }

    fn response(&self, now: Instant) -> PowerSample {
        let mut response =
            if let Some((sampled_at, sample)) = &self.last_good {
                let age = now.saturating_duration_since(*sampled_at);
                if age <= POWER_CACHE_TTL {
                    let mut response = add_cache_age(sample.clone(), age);
                    response.reason = self.last_error.as_ref().map(|error| {
                        format!("last refresh failed: {error}; serving the last good sample")
                    });
                    response
                } else {
                    let age_seconds = age.as_secs();
                    let detail = self
                        .last_error
                        .as_ref()
                        .map(|error| format!("; latest refresh failed: {error}"))
                        .unwrap_or_default();
                    unavailable(format!(
                        "last valid power sample is {age_seconds}s old (limit {}s){detail}",
                        POWER_CACHE_TTL.as_secs()
                    ))
                }
            } else {
                unavailable(self.last_error.clone().unwrap_or_else(|| {
                    "initial sample is pending; waiting for powermetrics".into()
                }))
            };

        if let Some((sampled_at, sample)) = self.last_good_gpu {
            let age = now.saturating_duration_since(sampled_at);
            if age <= GPU_CACHE_TTL {
                response.gpu_percent = Some(sample.percent);
                response.gpu_source = Some(sample.source.into());
                response.gpu_age_ms = Some(duration_ms(age));
                response.gpu_window_ms = Some(sample.window_ms);
                response.gpu_reason = self.gpu_error.clone();
            } else {
                response.gpu_reason = Some(format!(
                    "last valid GPU sample is {}s old (limit {}s)",
                    age.as_secs(),
                    GPU_CACHE_TTL.as_secs()
                ));
            }
        } else {
            response.gpu_reason = Some(
                self.gpu_error
                    .clone()
                    .unwrap_or_else(|| "initial GPU sample is pending".into()),
            );
        }
        response
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => {
            let sample = sample_powermetrics();
            println!(
                "{}",
                serde_json::to_string(&sample).expect("power sample serializes")
            );
            Ok(())
        }
        [command, uid] if command == "--serve" => uid
            .parse::<libc::uid_t>()
            .map_err(|_| "--serve requires a numeric peer UID".to_owned())
            .and_then(serve),
        [command] if command == "--nfs-admin" => nfs_admin::client(),
        [command] if command == "--version" => {
            println!("macluster-power {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err("usage: macluster-power [--version | --serve PEER_UID | --nfs-admin]".to_owned()),
    };
    if let Err(error) = result {
        eprintln!("macluster-power: {error}");
        std::process::exit(if error.starts_with("NFS_ADMIN_UNAVAILABLE:") {
            78
        } else {
            1
        });
    }
}

fn serve(peer_uid: libc::uid_t) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("--serve must run as root (use its LaunchDaemon)".into());
    }
    if peer_uid == 0 {
        return Err("peer UID must be a non-root account".into());
    }
    nfs_admin::start(peer_uid)?;
    let path = Path::new(POWER_SOCKET);
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|error| format!("remove stale socket: {error}"))?;
        }
        Ok(_) => return Err(format!("refusing to replace non-socket {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect socket path: {error}")),
    }
    let listener = UnixListener::bind(path).map_err(|error| format!("bind socket: {error}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .map_err(|error| format!("set socket permissions: {error}"))?;

    let cache = Arc::new(Mutex::new(PowerCache::default()));
    let sampler_cache = Arc::clone(&cache);
    thread::Builder::new()
        .name("macluster-power-sampler".into())
        .spawn(move || {
            let mut gpu_sampler = GpuSampler::new();
            loop {
                let iteration_started = Instant::now();
                let (gpu, macmon_power, temperature) = match &mut gpu_sampler {
                    Ok(sampler) => sampler.sample(),
                    Err(error) => (Err(error.clone()), None, None),
                };
                let sample = macmon_power
                    .map(power_sample_from_reading)
                    .unwrap_or_else(sample_powermetrics);
                let mut cache = sampler_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                cache.update(sample, gpu, temperature, Instant::now());
                drop(cache);
                thread::sleep(POWER_REFRESH_INTERVAL.saturating_sub(iteration_started.elapsed()));
            }
        })
        .map_err(|error| format!("start power sampler: {error}"))?;

    start_optional_fan_service(|| fan::start(peer_uid, Arc::clone(&cache)));

    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|error| format!("accept socket client: {error}"))?;
        serve_power_client(&mut stream, peer_uid, &cache)?;
    }
    Ok(())
}

fn serve_power_client(
    stream: &mut UnixStream,
    peer_uid: libc::uid_t,
    cache: &Mutex<PowerCache>,
) -> Result<(), String> {
    if peer_uid_for(&stream).ok() != Some(peer_uid) {
        let _ = stream.write_all(b"{\"watts\":null,\"scope\":null,\"available\":false,\"reason\":\"unauthorized local user\"}\n");
        return Ok(());
    }
    let response = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .response(Instant::now());
    let mut bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if let Err(error) = stream.write_all(&bytes)
        && !is_disconnected_client_error(&error)
    {
        return Err(format!("write sample: {error}"));
    }
    Ok(())
}

fn start_optional_fan_service(start: impl FnOnce() -> Result<(), String>) {
    if let Err(error) = start() {
        eprintln!(
            "macluster-power: fan control unavailable: {error}; power/GPU sampling continues"
        );
    }
}

fn is_disconnected_client_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
    )
}

fn peer_uid_for(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn sample_powermetrics() -> PowerSample {
    let mut failures = Vec::new();
    for samplers in [
        "cpu_power,gpu_power,ane_power",
        "cpu_power,gpu_power",
        "cpu_power",
    ] {
        let output = match run_powermetrics(samplers) {
            Ok(output) => output,
            Err(error) => {
                failures.push(format!("{samplers}: {error}"));
                continue;
            }
        };
        if !output.status.success() {
            let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            failures.push(if reason.is_empty() {
                format!("{samplers}: powermetrics exited with {}", output.status)
            } else {
                format!("{samplers}: {reason}")
            });
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(reading) = parse_powermetrics_power(&text) {
            return PowerSample {
                watts: Some(reading.watts),
                scope: Some(reading.scope.to_owned()),
                available: true,
                reason: None,
                age_ms: Some(0),
                gpu_percent: None,
                gpu_source: None,
                gpu_age_ms: None,
                gpu_window_ms: None,
                gpu_reason: None,
            };
        }
        failures.push(format!("{samplers}: no supported power scope in output"));
    }
    unavailable(failures.join("; "))
}

fn run_powermetrics(samplers: &str) -> Result<Output, String> {
    let mut child = match Command::new("/usr/bin/powermetrics")
        .args(["--samplers", samplers, "-n", "1", "-i", "1000"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Err(format!("could not start powermetrics: {error}")),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("powermetrics timed out".into());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not wait for powermetrics: {error}"));
            }
        }
    }
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => return Err(format!("could not collect powermetrics output: {error}")),
    };
    Ok(output)
}

fn unavailable(reason: String) -> PowerSample {
    PowerSample {
        watts: None,
        scope: None,
        available: false,
        reason: Some(reason),
        age_ms: None,
        gpu_percent: None,
        gpu_source: None,
        gpu_age_ms: None,
        gpu_window_ms: None,
        gpu_reason: None,
    }
}

fn add_cache_age(mut sample: PowerSample, cache_age: Duration) -> PowerSample {
    sample.age_ms = sample
        .age_ms
        .map(|age| age.saturating_add(cache_age.as_millis().min(u64::MAX as u128) as u64));
    sample
}

fn parse_powermetrics_power(input: &str) -> Option<PowerReading> {
    let mut cpu = None;
    for line in input.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let parsed = parse_power_value(value.trim());
        if label.contains("Combined Power") {
            if let Some(watts) = parsed {
                return Some(PowerReading {
                    watts,
                    scope: "SoC",
                });
            }
        } else if label.trim() == "CPU Power" {
            cpu = parsed.map(|watts| PowerReading {
                watts,
                scope: "CPU",
            });
        }
    }
    cpu
}

fn parse_power_value(input: &str) -> Option<f64> {
    let mut fields = input.split_whitespace();
    let value = fields.next()?.parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    match fields.next()? {
        "mW" => Some(value / 1000.0),
        "W" => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GPU_SAMPLE_WINDOW_MS, PowerCache, PowerReading, PowerSample, add_cache_age, gpu_reading,
        is_disconnected_client_error, macmon_power_reading, parse_powermetrics_power, unavailable,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn fan_start_failure_does_not_prevent_power_socket_response() {
        use std::{io::Read, os::unix::net::UnixStream, sync::Mutex};
        let mut cache = PowerCache::default();
        cache.update(
            good_sample(),
            Ok(gpu_reading(true, 0.5).unwrap()),
            None,
            Instant::now(),
        );
        super::start_optional_fan_service(|| Err("fan socket occupied".into()));
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        super::serve_power_client(&mut server, unsafe { libc::geteuid() }, &Mutex::new(cache))
            .unwrap();
        drop(server);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        let response: PowerSample = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response.watts, Some(3.5));
        assert_eq!(response.gpu_percent, Some(50.0));
    }

    fn good_sample() -> PowerSample {
        PowerSample {
            watts: Some(3.5),
            scope: Some("SoC".into()),
            available: true,
            reason: None,
            age_ms: Some(0),
            gpu_percent: None,
            gpu_source: None,
            gpu_age_ms: None,
            gpu_window_ms: None,
            gpu_reason: None,
        }
    }

    #[test]
    fn power_cache_serves_last_success_with_age_after_temporary_refresh_failure() {
        let started = Instant::now();
        let mut cache = PowerCache::default();
        cache.update(
            good_sample(),
            Err("GPU sample pending".into()),
            None,
            started,
        );
        cache.update(
            PowerSample {
                watts: None,
                scope: None,
                available: false,
                reason: Some("powermetrics temporarily busy".into()),
                age_ms: None,
                gpu_percent: None,
                gpu_source: None,
                gpu_age_ms: None,
                gpu_window_ms: None,
                gpu_reason: None,
            },
            Err("macmon temporarily busy".into()),
            None,
            started + Duration::from_secs(4),
        );

        let response = cache.response(started + Duration::from_secs(7));

        assert!(response.available);
        assert_eq!(response.watts, Some(3.5));
        assert_eq!(response.age_ms, Some(7_000));
        assert!(response.reason.unwrap().contains("temporarily busy"));
    }

    #[test]
    fn power_cache_expires_a_last_good_sample_after_sixty_seconds() {
        let started = Instant::now();
        let mut cache = PowerCache::default();
        cache.update(
            good_sample(),
            Err("GPU sample pending".into()),
            None,
            started,
        );

        let response = cache.response(started + Duration::from_secs(61));

        assert!(!response.available);
        assert_eq!(response.watts, None);
        assert!(response.reason.unwrap().contains("61s"));
    }

    #[test]
    fn power_cache_explains_that_the_first_sample_is_pending() {
        let response = PowerCache::default().response(Instant::now());

        assert!(!response.available);
        assert!(response.reason.unwrap().contains("initial sample"));
    }

    #[test]
    fn gpu_active_residency_distinguishes_supported_idle_from_unsupported() {
        assert_eq!(gpu_reading(true, 0.0).unwrap().percent, 0.0);
        assert_eq!(gpu_reading(true, 0.375).unwrap().percent, 37.5);
        assert_eq!(
            gpu_reading(false, 0.0),
            Err("GPU utilization is not supported by this hardware")
        );
        assert!(gpu_reading(true, f32::NAN).is_err());
        assert!(gpu_reading(true, 1.01).is_err());
    }

    #[test]
    fn gpu_cache_is_independent_of_power_availability_and_expires_after_eight_seconds() {
        let started = Instant::now();
        let mut cache = PowerCache::default();
        cache.update(
            unavailable("powermetrics unavailable".into()),
            Ok(gpu_reading(true, 0.0).unwrap()),
            None,
            started,
        );

        let response = cache.response(started + Duration::from_secs(7));
        assert!(!response.available);
        assert_eq!(response.gpu_percent, Some(0.0));
        assert_eq!(response.gpu_source.as_deref(), Some("macmon"));
        assert_eq!(response.gpu_age_ms, Some(7_000));
        assert_eq!(response.gpu_window_ms, Some(GPU_SAMPLE_WINDOW_MS));

        let stale = cache.response(started + Duration::from_secs(9));
        assert_eq!(stale.gpu_percent, None);
        assert!(stale.gpu_reason.unwrap().contains("old"));
    }

    #[test]
    fn gpu_failure_does_not_expire_a_fresh_power_sample() {
        let started = Instant::now();
        let mut cache = PowerCache::default();
        cache.update(
            good_sample(),
            Ok(gpu_reading(true, 0.5).unwrap()),
            None,
            started,
        );
        cache.update(
            good_sample(),
            Err("temperature sensor temporarily unavailable".into()),
            None,
            started + Duration::from_secs(4),
        );

        let response = cache.response(started + Duration::from_secs(5));
        assert!(response.available);
        assert_eq!(response.watts, Some(3.5));
        assert_eq!(response.gpu_percent, Some(50.0));
        assert!(
            response
                .gpu_reason
                .unwrap()
                .contains("temporarily unavailable")
        );
    }

    #[test]
    fn client_disconnect_errors_are_ignored_but_service_errors_are_not() {
        assert!(is_disconnected_client_error(&std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        )));
        assert!(is_disconnected_client_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        )));
        assert!(!is_disconnected_client_error(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn parses_combined_soc_power_in_milliwatts() {
        let sample = parse_powermetrics_power(
            "CPU Power: 1200 mW\nGPU Power: 400 mW\nCombined Power (CPU + GPU + ANE): 1750 mW\n",
        );

        assert_eq!(
            sample,
            Some(PowerReading {
                watts: 1.75,
                scope: "SoC"
            })
        );
    }

    #[test]
    fn macmon_power_prefers_system_scope_and_falls_back_to_soc() {
        let system = macmon_power_reading(18.4, 12.7).unwrap();
        assert_eq!(system.scope, "System");
        assert!((system.watts - 18.4).abs() < 0.001);

        let soc = macmon_power_reading(0.0, 12.7).unwrap();
        assert_eq!(soc.scope, "SoC");
        assert!((soc.watts - 12.7).abs() < 0.001);

        assert_eq!(macmon_power_reading(0.0, 0.0), None);
        assert_eq!(macmon_power_reading(f32::NAN, f32::INFINITY), None);
    }

    #[test]
    fn falls_back_to_cpu_power_when_soc_total_is_unavailable() {
        let sample = parse_powermetrics_power("CPU Power: 2.5 W\nGPU Power: 0.8 W\n");

        assert_eq!(
            sample,
            Some(PowerReading {
                watts: 2.5,
                scope: "CPU"
            })
        );
    }

    #[test]
    fn does_not_invent_power_when_output_has_no_supported_scope() {
        assert_eq!(parse_powermetrics_power("CPU frequency: 1000 MHz\n"), None);
    }

    #[test]
    fn cached_response_reports_sample_age_without_mutating_the_cache() {
        let cached = PowerSample {
            watts: Some(3.5),
            scope: Some("SoC".into()),
            available: true,
            reason: None,
            age_ms: Some(0),
            gpu_percent: None,
            gpu_source: None,
            gpu_age_ms: None,
            gpu_window_ms: None,
            gpu_reason: None,
        };

        let response = add_cache_age(cached.clone(), Duration::from_millis(1400));

        assert_eq!(response.age_ms, Some(1400));
        assert_eq!(cached.age_ms, Some(0));
    }
}
