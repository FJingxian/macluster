//! Portable metric records and host-specific sampling.

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use macluster_protocol::types::MetricSnapshot;

pub fn sample_local() -> MetricSnapshot {
    macos::sample_local()
}

/// Collect readings that do not need a counter-delta window. mtop uses this
/// for its initial paint, then replaces it with a full-rate sample.
pub fn sample_local_fast() -> MetricSnapshot {
    macos::sample_local_fast()
}

pub fn unavailable(sampled_unix_ms: u64, reason: &str) -> MetricSnapshot {
    let mut errors = BTreeMap::new();
    errors.insert("sampler".into(), reason.into());
    MetricSnapshot {
        sampled_unix_ms,
        cpu_percent: None,
        cpu_max_percent: None,
        memory_total_bytes: None,
        memory_used_bytes: None,
        swap_used_bytes: None,
        disk_read_bytes_per_sec: None,
        disk_write_bytes_per_sec: None,
        network_rx_bytes_per_sec: None,
        network_tx_bytes_per_sec: None,
        power_watts: None,
        power_scope: None,
        cpu_temp_celsius: None,
        fan_speed_rpm: None,
        power_age_ms: None,
        gpu_percent: None,
        gpu_source: None,
        gpu_age_ms: None,
        gpu_window_ms: None,
        stale: false,
        errors,
    }
}

fn average_fan_speed_rpm(readings: &[u32]) -> Option<f64> {
    let (total, count) = readings
        .iter()
        .copied()
        .filter(|rpm| *rpm <= 100_000)
        .fold((0.0, 0_u32), |(total, count), rpm| {
            (total + f64::from(rpm), count + 1)
        });
    (count > 0).then_some(total / f64::from(count))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(target_vendor = "apple")]
mod macos {
    use super::{MetricSnapshot, average_fan_speed_rpm, now_ms};
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        os::unix::net::UnixStream,
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    const POWER_SOCKET: &str = "/var/run/org.macluster.power.sock";

    #[derive(Clone, serde::Deserialize)]
    struct PowerSample {
        watts: Option<f64>,
        scope: Option<String>,
        available: bool,
        reason: Option<String>,
        #[serde(default)]
        age_ms: Option<u64>,
        #[serde(default)]
        gpu_percent: Option<f64>,
        #[serde(default)]
        gpu_source: Option<String>,
        #[serde(default)]
        gpu_age_ms: Option<u64>,
        #[serde(default)]
        gpu_window_ms: Option<u32>,
        #[serde(default)]
        gpu_reason: Option<String>,
    }

    #[derive(Default)]
    struct PowerMetrics {
        watts: Option<f64>,
        scope: Option<String>,
        age_ms: Option<u64>,
        gpu_percent: Option<f64>,
        gpu_source: Option<String>,
        gpu_age_ms: Option<u64>,
        gpu_window_ms: Option<u32>,
    }

    #[derive(Default)]
    struct HardwareMetrics {
        cpu_temp_celsius: Option<f64>,
        fan_speed_rpm: Option<f64>,
        cpu_temp_error: Option<String>,
        gpu_percent: Option<f64>,
        gpu_window_ms: Option<u32>,
        gpu_error: Option<String>,
    }

    type MachPort = u32;
    type KernReturn = i32;
    const PROCESSOR_CPU_LOAD_INFO: i32 = 2;
    const CPU_STATES: usize = 4;
    const CPU_STATE_IDLE: usize = 2;

    unsafe extern "C" {
        fn mach_host_self() -> MachPort;
        static mach_task_self_: MachPort;
        fn host_processor_info(
            host: MachPort,
            flavor: i32,
            cpu_count: *mut u32,
            info: *mut *mut i32,
            info_count: *mut u32,
        ) -> KernReturn;
        fn vm_deallocate(task: MachPort, address: u64, size: u64) -> KernReturn;
    }

    #[derive(Clone, Copy)]
    struct CpuCounters {
        busy: u64,
        total: u64,
        cpus: u32,
    }

    pub fn sample_local() -> MetricSnapshot {
        let sampled_unix_ms = now_ms();
        let mut errors = BTreeMap::new();
        let cpu_before = cpu_counters();
        let network_before = network_totals();
        let disk_before = disk_totals();
        thread::sleep(Duration::from_millis(500));
        let cpu_after = cpu_counters();
        let network_after = network_totals();
        let disk_after = disk_totals();

        let (cpu_percent, cpu_max_percent) = match (cpu_before, cpu_after) {
            (Ok(before), Ok(after)) if before.cpus == after.cpus => {
                match cpu_utilization(before, after) {
                    Some(value) => (Some(value), Some(after.cpus as f64 * 100.0)),
                    None => {
                        errors.insert("cpu".into(), "CPU counters reset or did not advance".into());
                        (None, Some(after.cpus as f64 * 100.0))
                    }
                }
            }
            (Err(error), _) | (_, Err(error)) => {
                errors.insert("cpu".into(), error);
                (None, None)
            }
            _ => {
                errors.insert("cpu".into(), "CPU count changed while sampling".into());
                (None, None)
            }
        };

        let (memory_total_bytes, memory_used_bytes, swap_used_bytes) = memory_sample(&mut errors);
        let elapsed = 0.5;
        let (network_rx_bytes_per_sec, network_tx_bytes_per_sec) =
            match (network_before, network_after) {
                (Ok(before), Ok(after)) => (
                    Some(after.0.saturating_sub(before.0) as f64 / elapsed),
                    Some(after.1.saturating_sub(before.1) as f64 / elapsed),
                ),
                (Err(error), _) | (_, Err(error)) => {
                    errors.insert("network".into(), error);
                    (None, None)
                }
            };
        let (disk_read_bytes_per_sec, disk_write_bytes_per_sec) = match (disk_before, disk_after) {
            (Ok(before), Ok(after)) if after.0 >= before.0 && after.1 >= before.1 => (
                Some((after.0 - before.0) as f64 / elapsed),
                Some((after.1 - before.1) as f64 / elapsed),
            ),
            (Err(error), _) | (_, Err(error)) => {
                errors.insert("disk_io".into(), error);
                (None, None)
            }
            _ => {
                errors.insert(
                    "disk_io".into(),
                    "disk counters reset during sampling".into(),
                );
                (None, None)
            }
        };
        let mut power = power_sample(&mut errors);
        let hardware = sample_hardware_metrics();
        if let Some(error) = hardware.cpu_temp_error.as_ref() {
            errors.insert("cpu_temp".into(), error.clone());
        }
        apply_gpu_fallback(&mut power, &hardware, &mut errors);
        MetricSnapshot {
            sampled_unix_ms,
            cpu_percent,
            cpu_max_percent,
            memory_total_bytes,
            memory_used_bytes,
            swap_used_bytes,
            disk_read_bytes_per_sec,
            disk_write_bytes_per_sec,
            network_rx_bytes_per_sec,
            network_tx_bytes_per_sec,
            power_watts: power.watts,
            power_scope: power.scope,
            cpu_temp_celsius: hardware.cpu_temp_celsius,
            fan_speed_rpm: hardware.fan_speed_rpm,
            power_age_ms: power.age_ms,
            gpu_percent: power.gpu_percent,
            gpu_source: power.gpu_source,
            gpu_age_ms: power.gpu_age_ms,
            gpu_window_ms: power.gpu_window_ms,
            stale: false,
            errors,
        }
    }

    pub fn sample_local_fast() -> MetricSnapshot {
        let sampled_unix_ms = now_ms();
        let mut errors = BTreeMap::new();
        let cpu_max_percent = match cpu_counters() {
            Ok(counters) => Some(counters.cpus as f64 * 100.0),
            Err(error) => {
                errors.insert("cpu".into(), error);
                None
            }
        };
        let (memory_total_bytes, memory_used_bytes, swap_used_bytes) = memory_sample(&mut errors);
        let mut power = power_sample(&mut errors);
        let hardware = sample_hardware_metrics();
        if let Some(error) = hardware.cpu_temp_error.as_ref() {
            errors.insert("cpu_temp".into(), error.clone());
        }
        apply_gpu_fallback(&mut power, &hardware, &mut errors);
        MetricSnapshot {
            sampled_unix_ms,
            cpu_percent: None,
            cpu_max_percent,
            memory_total_bytes,
            memory_used_bytes,
            swap_used_bytes,
            disk_read_bytes_per_sec: None,
            disk_write_bytes_per_sec: None,
            network_rx_bytes_per_sec: None,
            network_tx_bytes_per_sec: None,
            power_watts: power.watts,
            power_scope: power.scope,
            cpu_temp_celsius: hardware.cpu_temp_celsius,
            fan_speed_rpm: hardware.fan_speed_rpm,
            power_age_ms: power.age_ms,
            gpu_percent: power.gpu_percent,
            gpu_source: power.gpu_source,
            gpu_age_ms: power.gpu_age_ms,
            gpu_window_ms: power.gpu_window_ms,
            stale: false,
            errors,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn sample_hardware_metrics() -> HardwareMetrics {
        let mut sampler = match macmon::Sampler::new() {
            Ok(sampler) => sampler,
            Err(error) => {
                let error = format!("could not initialize macmon: {error}");
                return HardwareMetrics {
                    cpu_temp_error: Some(error.clone()),
                    gpu_error: Some(error),
                    ..HardwareMetrics::default()
                };
            }
        };
        let soc = sampler.get_soc_info();
        let gpu_supported = soc.gpu_cores > 0 && soc.gpu_freqs.len() > 1;
        let sample = match sampler.get_metrics(100) {
            Ok(sample) => sample,
            Err(error) => {
                let error = format!("macmon sampling failed: {error}");
                return HardwareMetrics {
                    cpu_temp_error: Some(error.clone()),
                    gpu_error: Some(error),
                    ..HardwareMetrics::default()
                };
            }
        };

        let (cpu_temp_celsius, cpu_temp_error) = match sample.temp.cpu_temp_avg {
            Some(value) if valid_cpu_temperature(value) => (Some(value as f64), None),
            Some(_) => (
                None,
                Some("temperature sensor returned an invalid Celsius value".into()),
            ),
            None => (
                None,
                Some("no valid CPU temperature sensor reading is available".into()),
            ),
        };
        let (gpu_percent, gpu_error) =
            match validated_gpu_percent(gpu_supported, sample.gpu_active_ratio) {
                Ok(percent) => (Some(percent), None),
                Err(error) => (None, Some(error.into())),
            };
        HardwareMetrics {
            cpu_temp_celsius,
            fan_speed_rpm: average_fan_speed_rpm(
                &sample.fans.iter().map(|fan| fan.rpm).collect::<Vec<_>>(),
            ),
            cpu_temp_error,
            gpu_percent,
            gpu_window_ms: gpu_percent.map(|_| 100),
            gpu_error,
        }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn sample_hardware_metrics() -> HardwareMetrics {
        HardwareMetrics {
            cpu_temp_error: Some("CPU temperature sampling requires Apple Silicon".into()),
            gpu_error: Some("GPU utilization sampling requires Apple Silicon".into()),
            ..HardwareMetrics::default()
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn valid_cpu_temperature(value: f32) -> bool {
        value.is_finite() && value > 0.0 && value < 150.0
    }

    fn validated_gpu_percent(supported: bool, active_ratio: f32) -> Result<f64, &'static str> {
        if !supported {
            return Err("GPU utilization is not supported by this hardware");
        }
        if !active_ratio.is_finite() || !(0.0..=1.0).contains(&active_ratio) {
            return Err("macmon returned an invalid GPU active residency ratio");
        }
        Ok(f64::from(active_ratio) * 100.0)
    }

    fn apply_gpu_fallback(
        power: &mut PowerMetrics,
        hardware: &HardwareMetrics,
        errors: &mut BTreeMap<String, String>,
    ) {
        if power.gpu_percent.is_some() {
            return;
        }
        match (hardware.gpu_percent, hardware.gpu_window_ms) {
            (Some(percent), Some(window_ms))
                if percent.is_finite() && (0.0..=100.0).contains(&percent) && window_ms > 0 =>
            {
                power.gpu_percent = Some(percent);
                power.gpu_source = Some("macmon".into());
                power.gpu_age_ms = Some(0);
                power.gpu_window_ms = Some(window_ms);
                errors.remove("gpu");
            }
            _ => {
                if let Some(error) = hardware.gpu_error.as_ref() {
                    errors.insert("gpu".into(), error.clone());
                } else {
                    errors.entry("gpu".into()).or_insert_with(|| {
                        "GPU sample unavailable from both the helper and macmon".into()
                    });
                }
            }
        }
    }

    fn power_sample(errors: &mut BTreeMap<String, String>) -> PowerMetrics {
        let request_started = Instant::now();
        let result = (|| -> Result<PowerSample, String> {
            let mut stream =
                UnixStream::connect(POWER_SOCKET).map_err(|error| match error.kind() {
                    std::io::ErrorKind::NotFound => {
                        "power helper socket is missing; rerun mnode to install the power sampler"
                            .to_owned()
                    }
                    std::io::ErrorKind::ConnectionRefused => {
                        "power helper is not running; rerun mnode to restart the power sampler"
                            .to_owned()
                    }
                    _ => format!("power helper unavailable: {error}"),
                })?;
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            stream
                .write_all(b"sample\n")
                .map_err(|error| format!("power helper request failed: {error}"))?;
            let mut response = Vec::new();
            stream
                .take(16 * 1024)
                .read_to_end(&mut response)
                .map_err(|error| format!("power helper response failed: {error}"))?;
            serde_json::from_slice(&response)
                .map_err(|error| format!("power helper returned invalid JSON: {error}"))
        })();
        match result {
            Ok(sample) => {
                let request_age = request_started.elapsed();
                let power = power_response(sample.clone(), request_age, errors);
                let gpu = gpu_response(sample, request_age, errors);
                PowerMetrics {
                    watts: power.0,
                    scope: power.1,
                    age_ms: power.2,
                    gpu_percent: gpu.0,
                    gpu_source: gpu.1,
                    gpu_age_ms: gpu.2,
                    gpu_window_ms: gpu.3,
                }
            }
            Err(error) => {
                errors.insert("power".into(), error.clone());
                errors.insert("gpu".into(), format!("GPU helper unavailable: {error}"));
                PowerMetrics::default()
            }
        }
    }

    fn gpu_response(
        sample: PowerSample,
        request_age: Duration,
        errors: &mut BTreeMap<String, String>,
    ) -> (Option<f64>, Option<String>, Option<u64>, Option<u32>) {
        let request_age_ms = request_age.as_millis().min(u64::MAX as u128) as u64;
        let result = match (
            sample.gpu_percent,
            sample.gpu_source,
            sample.gpu_age_ms,
            sample.gpu_window_ms,
        ) {
            (Some(percent), Some(source), Some(age_ms), Some(window_ms))
                if percent.is_finite() && (0.0..=100.0).contains(&percent) && window_ms > 0 =>
            {
                (
                    Some(percent),
                    Some(source),
                    Some(age_ms.saturating_add(request_age_ms)),
                    Some(window_ms),
                )
            }
            _ => {
                errors.insert(
                    "gpu".into(),
                    sample.gpu_reason.clone().unwrap_or_else(|| {
                        "GPU sample unavailable; rerun mnode -a to update the helper".into()
                    }),
                );
                (None, None, None, None)
            }
        };
        if let Some(reason) = sample.gpu_reason {
            errors.insert("gpu".into(), reason);
        }
        result
    }

    fn power_response(
        sample: PowerSample,
        request_age: Duration,
        errors: &mut BTreeMap<String, String>,
    ) -> (Option<f64>, Option<String>, Option<u64>) {
        if !sample.available {
            errors.insert(
                "power".into(),
                sample
                    .reason
                    .unwrap_or_else(|| "power sampler unavailable".into()),
            );
            return (None, None, None);
        }
        match (sample.watts, sample.scope) {
            (Some(watts), Some(scope)) if watts.is_finite() && watts >= 0.0 => {
                let request_age_ms = request_age.as_millis().min(u64::MAX as u128) as u64;
                let age_ms = sample.age_ms.map(|age| age.saturating_add(request_age_ms));
                if let Some(reason) = sample.reason {
                    errors.insert("power".into(), reason);
                }
                (Some(watts), Some(scope), age_ms)
            }
            _ => {
                errors.insert(
                    "power".into(),
                    "helper returned an incomplete power sample".into(),
                );
                (None, None, None)
            }
        }
    }

    #[cfg(test)]
    mod power_tests {
        use super::{
            HardwareMetrics, PowerMetrics, PowerSample, apply_gpu_fallback, gpu_response,
            power_response, validated_gpu_percent,
        };
        use std::{collections::BTreeMap, time::Duration};

        #[test]
        fn cached_power_is_kept_while_helper_refresh_warning_is_exposed() {
            let sample = PowerSample {
                watts: Some(4.2),
                scope: Some("SoC".into()),
                available: true,
                reason: Some("last refresh failed: busy; serving cached value".into()),
                age_ms: Some(5_000),
                gpu_percent: None,
                gpu_source: None,
                gpu_age_ms: None,
                gpu_window_ms: None,
                gpu_reason: None,
            };
            let mut errors = BTreeMap::new();
            let reading = power_response(sample, Duration::from_millis(200), &mut errors);

            assert_eq!(reading, (Some(4.2), Some("SoC".into()), Some(5_200)));
            assert!(errors["power"].contains("serving cached value"));
        }

        #[test]
        fn gpu_sample_is_retained_when_power_is_unavailable_and_has_its_own_age() {
            let sample = PowerSample {
                watts: None,
                scope: None,
                available: false,
                reason: Some("powermetrics unavailable".into()),
                age_ms: None,
                gpu_percent: Some(42.5),
                gpu_source: Some("macmon".into()),
                gpu_age_ms: Some(3_000),
                gpu_window_ms: Some(100),
                gpu_reason: Some("temperature read failed; serving recent GPU sample".into()),
            };
            let mut errors = BTreeMap::new();
            let reading = gpu_response(sample, Duration::from_millis(200), &mut errors);

            assert_eq!(
                reading,
                (Some(42.5), Some("macmon".into()), Some(3_200), Some(100))
            );
            assert!(errors["gpu"].contains("serving recent GPU sample"));
        }

        #[test]
        fn invalid_gpu_samples_are_unavailable_without_affecting_power() {
            let sample = PowerSample {
                watts: Some(4.2),
                scope: Some("SoC".into()),
                available: true,
                reason: None,
                age_ms: Some(0),
                gpu_percent: Some(101.0),
                gpu_source: Some("macmon".into()),
                gpu_age_ms: Some(0),
                gpu_window_ms: Some(100),
                gpu_reason: None,
            };
            let mut errors = BTreeMap::new();
            let power = power_response(sample.clone(), Duration::ZERO, &mut errors);
            let gpu = gpu_response(sample, Duration::ZERO, &mut errors);

            assert_eq!(power, (Some(4.2), Some("SoC".into()), Some(0)));
            assert_eq!(gpu, (None, None, None, None));
            assert!(errors["gpu"].contains("GPU sample unavailable"));
        }

        #[test]
        fn agent_sampler_fills_gpu_when_an_existing_helper_has_no_gpu_fields() {
            let mut power = PowerMetrics::default();
            let hardware = HardwareMetrics {
                cpu_temp_celsius: Some(48.0),
                cpu_temp_error: None,
                fan_speed_rpm: None,
                gpu_percent: Some(0.0),
                gpu_window_ms: Some(100),
                gpu_error: None,
            };
            let mut errors = BTreeMap::from([("gpu".into(), "old helper".into())]);

            apply_gpu_fallback(&mut power, &hardware, &mut errors);

            assert_eq!(power.gpu_percent, Some(0.0));
            assert_eq!(power.gpu_source.as_deref(), Some("macmon"));
            assert_eq!(power.gpu_age_ms, Some(0));
            assert_eq!(power.gpu_window_ms, Some(100));
            assert!(!errors.contains_key("gpu"));
        }

        #[test]
        fn cached_helper_gpu_is_preferred_and_keeps_its_sample_age() {
            let mut power = PowerMetrics {
                gpu_percent: Some(73.5),
                gpu_source: Some("macmon-helper".into()),
                gpu_age_ms: Some(1_250),
                gpu_window_ms: Some(100),
                ..PowerMetrics::default()
            };
            let hardware = HardwareMetrics {
                gpu_percent: Some(0.0),
                gpu_window_ms: Some(100),
                ..HardwareMetrics::default()
            };
            let mut errors = BTreeMap::new();

            apply_gpu_fallback(&mut power, &hardware, &mut errors);

            assert_eq!(power.gpu_percent, Some(73.5));
            assert_eq!(power.gpu_age_ms, Some(1_250));
        }

        #[test]
        fn gpu_residency_validation_accepts_idle_and_rejects_unsupported_or_invalid_values() {
            assert_eq!(validated_gpu_percent(true, 0.0), Ok(0.0));
            assert_eq!(validated_gpu_percent(true, 1.0), Ok(100.0));
            assert!(validated_gpu_percent(false, 0.0).is_err());
            assert!(validated_gpu_percent(true, f32::NAN).is_err());
            assert!(validated_gpu_percent(true, 1.01).is_err());
        }
    }

    fn cpu_counters() -> Result<CpuCounters, String> {
        let mut cpu_count = 0_u32;
        let mut info = std::ptr::null_mut();
        let mut info_count = 0_u32;
        let result = unsafe {
            host_processor_info(
                mach_host_self(),
                PROCESSOR_CPU_LOAD_INFO,
                &mut cpu_count,
                &mut info,
                &mut info_count,
            )
        };
        if result != 0 {
            return Err(format!("host_processor_info returned {result}"));
        }
        let expected = cpu_count as usize * CPU_STATES;
        if info.is_null() || (info_count as usize) < expected {
            if !info.is_null() {
                unsafe {
                    vm_deallocate(mach_task_self_, info as usize as u64, info_count as u64 * 4);
                }
            }
            return Err("host_processor_info returned a truncated CPU array".into());
        }
        let states = unsafe { std::slice::from_raw_parts(info, expected) };
        let mut busy = 0_u64;
        let mut total = 0_u64;
        for cpu in states.chunks_exact(CPU_STATES) {
            let mut core_total = 0_u64;
            for state in cpu {
                core_total += *state as u32 as u64;
            }
            let idle = cpu[CPU_STATE_IDLE] as u32 as u64;
            total += core_total;
            busy += core_total.saturating_sub(idle);
        }
        unsafe {
            vm_deallocate(mach_task_self_, info as usize as u64, info_count as u64 * 4);
        }
        Ok(CpuCounters {
            busy,
            total,
            cpus: cpu_count,
        })
    }

    fn cpu_utilization(before: CpuCounters, after: CpuCounters) -> Option<f64> {
        if before.cpus != after.cpus || after.busy < before.busy || after.total <= before.total {
            return None;
        }
        let busy = after.busy - before.busy;
        let total = after.total - before.total;
        Some((busy as f64 / total as f64) * after.cpus as f64 * 100.0)
    }

    fn memory_sample(
        errors: &mut BTreeMap<String, String>,
    ) -> (Option<u64>, Option<u64>, Option<u64>) {
        let total = Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .filter(|result| result.status.success())
            .and_then(|result| String::from_utf8(result.stdout).ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        let vm = Command::new("/usr/bin/vm_stat").output();
        let used = match vm {
            Ok(output) if output.status.success() => {
                match String::from_utf8(output.stdout)
                    .ok()
                    .and_then(|text| parse_vm_stat(&text))
                {
                    Some((available, _)) => {
                        total.map(|total| total.saturating_sub(available.min(total)))
                    }
                    None => {
                        errors.insert("memory".into(), "could not parse vm_stat counters".into());
                        None
                    }
                }
            }
            _ => {
                errors.insert("memory".into(), "vm_stat failed".into());
                None
            }
        };
        let total = total.or_else(|| {
            errors.insert("memory".into(), "hw.memsize query failed".into());
            None
        });
        (total, used, None)
    }

    fn parse_vm_stat(input: &str) -> Option<(u64, u64)> {
        let page_bytes = input
            .lines()
            .next()?
            .split("page size of ")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?;
        let mut free = None;
        let mut inactive = None;
        for line in input.lines() {
            if let Some(value) = line.strip_prefix("Pages free:") {
                free = parse_pages(value);
            }
            if let Some(value) = line.strip_prefix("Pages inactive:") {
                inactive = parse_pages(value);
            }
        }
        let free = free?;
        let inactive = inactive?;
        Some((
            (free.saturating_add(inactive)).saturating_mul(page_bytes),
            page_bytes,
        ))
    }

    fn parse_pages(value: &str) -> Option<u64> {
        value
            .trim()
            .trim_end_matches('.')
            .replace(',', "")
            .parse()
            .ok()
    }

    fn network_totals() -> Result<(u64, u64), String> {
        let output = Command::new("/usr/sbin/netstat")
            .args(["-ibn"])
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("netstat -ibn failed".into());
        }
        let text = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
        parse_netstat(&text).ok_or_else(|| "could not parse interface byte counters".into())
    }

    fn disk_totals() -> Result<(u64, u64), String> {
        let output = Command::new("/usr/sbin/ioreg")
            .args(["-r", "-c", "IOBlockStorageDriver", "-d", "1", "-l"])
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("ioreg storage counter query failed".into());
        }
        let text = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
        parse_ioreg_storage(&text).ok_or_else(|| "could not parse storage byte counters".into())
    }

    fn parse_ioreg_storage(input: &str) -> Option<(u64, u64)> {
        let mut read = 0_u64;
        let mut write = 0_u64;
        let mut devices = 0_u64;
        for line in input
            .lines()
            .filter(|line| line.contains("\"Statistics\" = {"))
        {
            let read_bytes = parse_ioreg_value(line, "Bytes (Read)")?;
            let write_bytes = parse_ioreg_value(line, "Bytes (Write)")?;
            read = read.saturating_add(read_bytes);
            write = write.saturating_add(write_bytes);
            devices += 1;
        }
        (devices > 0).then_some((read, write))
    }

    fn parse_ioreg_value(line: &str, key: &str) -> Option<u64> {
        let marker = format!("\"{key}\"=");
        let value = line.split_once(&marker)?.1;
        value
            .split(|character: char| !character.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    }

    fn parse_netstat(input: &str) -> Option<(u64, u64)> {
        let mut headers = None;
        let mut totals = (0_u64, 0_u64);
        let mut interfaces = 0_u64;
        for line in input.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.iter().any(|field| *field == "Ibytes")
                && fields.iter().any(|field| *field == "Obytes")
            {
                headers = Some(fields);
                continue;
            }
            let Some(columns) = headers.as_ref() else {
                continue;
            };
            if fields.first().is_none_or(|name| !name.starts_with("en")) {
                continue;
            }
            let Some(i) = columns.iter().position(|field| *field == "Ibytes") else {
                continue;
            };
            let Some(o) = columns.iter().position(|field| *field == "Obytes") else {
                continue;
            };
            let Some(rx) = fields.get(i).and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let Some(tx) = fields.get(o).and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            totals.0 = totals.0.saturating_add(rx);
            totals.1 = totals.1.saturating_add(tx);
            interfaces += 1;
        }
        (interfaces > 0).then_some(totals)
    }

    #[cfg(test)]
    pub(super) fn parse_vm_stat_fixture(input: &str) -> Option<(u64, u64)> {
        parse_vm_stat(input)
    }
    #[cfg(test)]
    pub(super) fn parse_netstat_fixture(input: &str) -> Option<(u64, u64)> {
        parse_netstat(input)
    }
    #[cfg(test)]
    pub(super) fn parse_ioreg_fixture(input: &str) -> Option<(u64, u64)> {
        parse_ioreg_storage(input)
    }
    #[cfg(test)]
    pub(super) fn cpu_utilization_fixture(
        before: (u64, u64, u32),
        after: (u64, u64, u32),
    ) -> Option<f64> {
        cpu_utilization(
            CpuCounters {
                busy: before.0,
                total: before.1,
                cpus: before.2,
            },
            CpuCounters {
                busy: after.0,
                total: after.1,
                cpus: after.2,
            },
        )
    }
}

#[cfg(not(target_vendor = "apple"))]
mod macos {
    use super::{MetricSnapshot, now_ms, unavailable};
    pub fn sample_local() -> MetricSnapshot {
        unavailable(
            now_ms(),
            "macOS metric sampling is not available on this platform",
        )
    }

    pub fn sample_local_fast() -> MetricSnapshot {
        sample_local()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fan_speed_is_the_average_of_readings_and_missing_fans_are_unavailable() {
        assert_eq!(super::average_fan_speed_rpm(&[]), None);
        assert_eq!(super::average_fan_speed_rpm(&[1500]), Some(1500.0));
        assert_eq!(super::average_fan_speed_rpm(&[1000, 2000]), Some(1500.0));
        assert_eq!(super::average_fan_speed_rpm(&[0, 2000]), Some(1000.0));
        assert_eq!(super::average_fan_speed_rpm(&[1000, 100_001]), Some(1000.0));
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn vm_stat_uses_only_free_and_inactive_pages() {
        let text = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\nPages inactive: 20.\nPages occupied by compressor: 999.\n";
        assert_eq!(
            super::macos::parse_vm_stat_fixture(text),
            Some((30 * 16384, 16384))
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn network_totals_ignore_loopback_and_tunnels() {
        let input = "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes\nen0 1500 link#4 aa 10 0 1000 11 0 2000\nlo0 16384 link#1 127 80 0 80000 80 0 90000\nutun0 1500 link#8 aa 20 0 9000 20 0 9000\nen1 1500 link#5 aa 1 0 500 1 0 600\n";
        assert_eq!(
            super::macos::parse_netstat_fixture(input),
            Some((1500, 2600))
        );
        assert_eq!(
            super::macos::parse_netstat_fixture(
                "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes\n"
            ),
            None
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn cpu_utilization_uses_logical_cpu_scale_and_rejects_resets() {
        assert_eq!(
            super::macos::cpu_utilization_fixture((100, 100, 8), (200, 900, 8)),
            Some(100.0)
        );
        assert_eq!(
            super::macos::cpu_utilization_fixture((100, 100, 8), (900, 900, 8)),
            Some(800.0)
        );
        assert_eq!(
            super::macos::cpu_utilization_fixture((500, 700, 8), (1, 2, 8)),
            None
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn disk_counters_sum_only_storage_driver_statistics() {
        let input = "    \"Statistics\" = {\"Bytes (Read)\"=1100,\"Bytes (Write)\"=2200}\n    \"Statistics\" = {\"Bytes (Read)\"=300,\"Bytes (Write)\"=400}\n";
        assert_eq!(super::macos::parse_ioreg_fixture(input), Some((1400, 2600)));
    }

    #[test]
    fn unavailable_metrics_are_not_reported_as_zero() {
        let snapshot = super::unavailable(1, "unsupported");
        assert_eq!(snapshot.cpu_percent, None);
        assert_eq!(snapshot.memory_used_bytes, None);
        assert_eq!(snapshot.cpu_temp_celsius, None);
        assert!(!snapshot.errors.is_empty());
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn native_sampler_subprocess() {
        const CHILD: &str = "MACLUSTER_METRICS_SAMPLER_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let snapshot = super::sample_local();
            match snapshot.cpu_temp_celsius {
                Some(value) => {
                    assert!(value.is_finite() && value > 0.0 && value < 150.0);
                    assert!(!snapshot.errors.contains_key("cpu_temp"));
                }
                None => assert!(snapshot.errors.contains_key("cpu_temp")),
            }
            match snapshot.gpu_percent {
                Some(value) => {
                    assert!(value.is_finite() && (0.0..=100.0).contains(&value));
                    assert!(snapshot.gpu_source.is_some());
                    assert!(snapshot.gpu_age_ms.is_some());
                    assert!(snapshot.gpu_window_ms.is_some_and(|window| window > 0));
                }
                None => assert!(snapshot.errors.contains_key("gpu")),
            }
            println!(
                "METRIC_SAMPLER_OK timestamp={} gpu={:?} gpu_source={:?} gpu_age_ms={:?} gpu_window_ms={:?} gpu_error={:?}",
                snapshot.sampled_unix_ms,
                snapshot.gpu_percent,
                snapshot.gpu_source,
                snapshot.gpu_age_ms,
                snapshot.gpu_window_ms,
                snapshot.errors.get("gpu"),
            );
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::native_sampler_subprocess", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "sampler child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("METRIC_SAMPLER_OK"));
        println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    }
}
