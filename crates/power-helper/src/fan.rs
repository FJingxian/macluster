//! Per-node fan policy engine and its root-owned local control socket.
//!
//! The controller sends policy changes once. This daemon then evaluates the
//! temperature curve locally, so fan control does not add periodic SSH traffic.

use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use macluster_protocol::types::{FanControlStatus, FanHelperCommand, FanHelperResponse, FanPolicy};

use crate::PowerCache;

const FAN_SOCKET: &str = "/var/run/org.macluster.fan.sock";
const MANUAL_MARKER: &str = "/var/run/org.macluster.fan.manual";
const FAN_TICK: Duration = Duration::from_secs(5);
const TEMP_WINDOW: usize = 5;
const RPM_CHANGE_THRESHOLD: u32 = 180;
const MIN_UPDATE_INTERVAL: Duration = Duration::from_secs(15);
const INITIAL_TEMP_GRACE: Duration = Duration::from_secs(30);
const FAN_ON_C: f32 = 40.0;
const FAN_OFF_C: f32 = 38.0;
const FAN_MAX_C: f32 = 80.0;

#[derive(Clone, Debug)]
struct FanInfo {
    mode_key: String,
    target_key: String,
    min_rpm: u32,
    max_rpm: u32,
}

struct FanEngine {
    policy: FanPolicy,
    supported: bool,
    active: bool,
    average_temperature_celsius: Option<f32>,
    target_rpm: Option<u32>,
    message: Option<String>,
    temperatures: VecDeque<f32>,
    initial_temperature_wait_since: Option<Instant>,
    saw_temperature: bool,
    fans: Vec<FanInfo>,
    last_targets: Vec<u32>,
    last_write: Option<Instant>,
    restore_pending: bool,
    hardware: Option<Hardware>,
}

impl FanEngine {
    fn new() -> Self {
        match Hardware::open() {
            Ok((mut hardware, fans)) if !fans.is_empty() => {
                // Do not override another fan utility at helper startup. The
                // marker records that macluster itself entered manual mode.
                let marker_exists = manual_marker_exists();
                hardware.ftst_engaged = marker_exists && hardware.ftst_available;
                let mut startup_error = if marker_exists {
                    hardware.restore_system(&fans).err()
                } else {
                    None
                };
                if startup_error.is_none() {
                    startup_error = remove_manual_marker().err();
                }
                let restore_pending = startup_error.is_some();
                Self {
                    policy: FanPolicy::System,
                    supported: true,
                    active: false,
                    average_temperature_celsius: None,
                    target_rpm: None,
                    message: Some(startup_error.map_or_else(
                        || "macOS controls fan speed".into(),
                        |error| {
                            format!("could not restore system fan mode at helper startup: {error}")
                        },
                    )),
                    temperatures: VecDeque::with_capacity(TEMP_WINDOW),
                    initial_temperature_wait_since: None,
                    saw_temperature: false,
                    fans,
                    last_targets: Vec::new(),
                    last_write: None,
                    restore_pending,
                    hardware: Some(hardware),
                }
            }
            Ok(_) => Self::unsupported("this Mac does not expose controllable fans"),
            Err(error) => Self::unsupported(&error),
        }
    }

    fn unsupported(reason: &str) -> Self {
        Self {
            policy: FanPolicy::System,
            supported: false,
            active: false,
            average_temperature_celsius: None,
            target_rpm: None,
            message: Some(reason.to_owned()),
            temperatures: VecDeque::with_capacity(TEMP_WINDOW),
            initial_temperature_wait_since: None,
            saw_temperature: false,
            fans: Vec::new(),
            last_targets: Vec::new(),
            last_write: None,
            restore_pending: false,
            hardware: None,
        }
    }

    fn status(&self) -> FanControlStatus {
        FanControlStatus {
            policy: self.policy,
            supported: self.supported,
            active: self.active,
            average_temperature_deci_celsius: self
                .average_temperature_celsius
                .map(|temperature| (temperature * 10.0).round() as u16),
            target_rpm: self.target_rpm,
            message: self.message.clone(),
        }
    }

    fn set_policy(&mut self, policy: FanPolicy) -> Result<(), String> {
        if policy == FanPolicy::System {
            self.policy = FanPolicy::System;
            self.temperatures.clear();
            self.initial_temperature_wait_since = None;
            self.saw_temperature = false;
            self.active = false;
            self.target_rpm = None;
            self.last_targets.clear();
            self.average_temperature_celsius = None;
            if let Some(hardware) = self.hardware.as_mut() {
                match hardware.restore_system(&self.fans) {
                    Ok(()) => {
                        self.restore_pending = false;
                        remove_manual_marker()?;
                    }
                    Err(error) => {
                        self.restore_pending = true;
                        self.last_write = Some(Instant::now());
                        self.message =
                            Some(format!("could not restore macOS fan control: {error}"));
                        return Err(error);
                    }
                }
            }
            self.message = Some("macOS controls fan speed".into());
            return Ok(());
        }
        if !self.supported || self.hardware.is_none() {
            return Err(self
                .message
                .clone()
                .unwrap_or_else(|| "fan control is unavailable on this node".into()));
        }
        if self.restore_pending {
            return Err(self
                .message
                .clone()
                .unwrap_or_else(|| "system fan restoration is still pending".into()));
        }
        self.arm_curve(policy);
        Ok(())
    }

    fn arm_curve(&mut self, policy: FanPolicy) {
        if self.policy == policy {
            return;
        }
        self.policy = policy;
        self.temperatures.clear();
        // Keep active hardware ownership/targets while switching curves.
        self.initial_temperature_wait_since = Some(Instant::now());
        self.saw_temperature = false;
        self.average_temperature_celsius = None;
        self.message = Some(
            "waiting for a fresh CPU temperature sample; macOS controls fans until activation"
                .into(),
        );
    }

    fn tick(&mut self, temperature: Option<f32>) {
        if !self.supported {
            return;
        }
        if self.policy == FanPolicy::System {
            if self.restore_pending
                && self
                    .last_write
                    .is_none_or(|last| last.elapsed() >= MIN_UPDATE_INTERVAL)
                && let Some(hardware) = self.hardware.as_mut()
            {
                match hardware.restore_system(&self.fans) {
                    Ok(()) => match remove_manual_marker() {
                        Ok(()) => {
                            self.restore_pending = false;
                            self.message = Some("macOS controls fan speed".into());
                        }
                        Err(error) => {
                            self.last_write = Some(Instant::now());
                            self.message = Some(format!("could not clear fan marker: {error}"));
                        }
                    },
                    Err(error) => {
                        self.last_write = Some(Instant::now());
                        self.message = Some(format!("system fan restore retry failed: {error}"));
                    }
                }
            }
            return;
        }
        let Some(temperature) =
            temperature.filter(|value| value.is_finite() && (0.0..=130.0).contains(value))
        else {
            if !self.active
                && !self.saw_temperature
                && self
                    .initial_temperature_wait_since
                    .is_some_and(|started| started.elapsed() < INITIAL_TEMP_GRACE)
            {
                self.message = Some("waiting for a fresh CPU temperature sample".into());
                return;
            }
            self.fallback_to_system("temperature sample expired; restored macOS fan control");
            return;
        };
        self.saw_temperature = true;
        self.initial_temperature_wait_since = None;
        self.temperatures.push_back(temperature);
        while self.temperatures.len() > TEMP_WINDOW {
            self.temperatures.pop_front();
        }
        let average = self.temperatures.iter().sum::<f32>() / self.temperatures.len() as f32;
        self.average_temperature_celsius = Some(average);

        if average <= FAN_OFF_C {
            if !self.active {
                self.message = Some("below 40°C; curve armed, macOS controls fan speed".into());
            }
            if self.active {
                if let Some(hardware) = self.hardware.as_mut()
                    && let Err(error) = hardware.restore_system(&self.fans)
                {
                    self.message = Some(format!("could not restore macOS fan control: {error}"));
                    return;
                }
                if let Err(error) = remove_manual_marker() {
                    self.fallback_to_system(&format!("could not clear manual fan marker: {error}"));
                    return;
                }
                self.active = false;
                self.target_rpm = None;
                self.last_targets.clear();
                self.message = Some("below 38°C; macOS controls fan speed".into());
            }
            return;
        }
        if average < FAN_ON_C && !self.active {
            self.message = Some("curve armed; waiting for the 40°C activation threshold".into());
            return;
        }

        let fraction = curve_fraction(self.policy, average);
        let targets = self
            .fans
            .iter()
            .map(|fan| {
                let span = fan.max_rpm.saturating_sub(fan.min_rpm);
                fan.min_rpm
                    .saturating_add((span as f32 * fraction).round() as u32)
                    .clamp(fan.min_rpm, fan.max_rpm)
            })
            .collect::<Vec<_>>();
        let at_maximum_temperature = average >= FAN_MAX_C && targets != self.last_targets;
        let manual_mode_lost = if self.active {
            match self
                .hardware
                .as_ref()
                .ok_or_else(|| "AppleSMC connection is unavailable".to_owned())
                .and_then(|hardware| hardware.manual_mode_lost(&self.fans))
            {
                Ok(lost) => lost,
                Err(error) => {
                    self.fallback_to_system(&format!(
                        "could not verify manual fan control; restored macOS fan control: {error}"
                    ));
                    return;
                }
            }
        } else {
            false
        };
        let changed_enough = self.active
            && targets
                .iter()
                .zip(&self.last_targets)
                .any(|(target, previous)| target.abs_diff(*previous) >= RPM_CHANGE_THRESHOLD);
        let elapsed = self
            .last_write
            .is_none_or(|last| last.elapsed() >= MIN_UPDATE_INTERVAL);
        let should_write = !self.active
            || ((manual_mode_lost || changed_enough) && elapsed)
            || at_maximum_temperature;
        if !should_write {
            return;
        }

        match self
            .hardware
            .as_mut()
            .ok_or_else(|| "AppleSMC connection is unavailable".to_owned())
            .and_then(|hardware| {
                create_manual_marker()?;
                hardware.set_targets(&self.fans, &targets)
            }) {
            Ok(()) => {
                self.active = true;
                self.last_targets = targets.clone();
                self.last_write = Some(Instant::now());
                self.target_rpm =
                    Some(targets.iter().copied().sum::<u32>() / targets.len().max(1) as u32);
                self.message = Some(format!("{} curve active", policy_name(self.policy)));
            }
            Err(error) => self.fallback_to_system(&format!(
                "fan write failed; restored macOS fan control: {error}"
            )),
        }
    }

    fn fallback_to_system(&mut self, reason: &str) {
        let restore_error = self
            .hardware
            .as_mut()
            .and_then(|hardware| hardware.restore_system(&self.fans).err());
        let restore_error = restore_error.or_else(|| remove_manual_marker().err());
        self.policy = FanPolicy::System;
        self.active = false;
        self.target_rpm = None;
        self.last_targets.clear();
        self.average_temperature_celsius = None;
        self.temperatures.clear();
        self.initial_temperature_wait_since = None;
        self.saw_temperature = false;
        self.restore_pending = restore_error.is_some();
        if self.restore_pending {
            self.last_write = Some(Instant::now());
        }
        self.message = Some(restore_error.map_or_else(
            || reason.to_owned(),
            |error| format!("{reason}; automatic restore retry is pending: {error}"),
        ));
    }
}

fn policy_name(policy: FanPolicy) -> &'static str {
    match policy {
        FanPolicy::System => "system",
        FanPolicy::Auto => "linear",
        FanPolicy::Power => "power",
    }
}

fn curve_fraction(policy: FanPolicy, temperature: f32) -> f32 {
    let x = ((temperature - FAN_ON_C) / (FAN_MAX_C - FAN_ON_C)).clamp(0.0, 1.0);
    match policy {
        FanPolicy::System => 0.0,
        FanPolicy::Auto => x,
        FanPolicy::Power => ((1.0 + 9.0 * x).ln() / 10.0_f32.ln()).clamp(0.0, 1.0),
    }
}

pub fn start(peer_uid: libc::uid_t, power_cache: Arc<Mutex<PowerCache>>) -> Result<(), String> {
    let socket_path = Path::new(FAN_SOCKET);
    match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(socket_path)
                .map_err(|error| format!("remove stale fan socket: {error}"))?;
        }
        Ok(_) => {
            return Err(format!(
                "refusing to replace non-socket {}",
                socket_path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect fan socket: {error}")),
    }
    let listener =
        UnixListener::bind(socket_path).map_err(|error| format!("bind fan socket: {error}"))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
        .map_err(|error| format!("set fan socket permissions: {error}"))?;

    let engine = Arc::new(Mutex::new(FanEngine::new()));
    let listener_engine = Arc::clone(&engine);
    let listener_cache = Arc::clone(&power_cache);

    thread::Builder::new()
        .name("macluster-fan-policy".into())
        .spawn(move || {
            loop {
                thread::sleep(FAN_TICK);
                let temperature = power_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .temperature(Instant::now());
                engine
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .tick(temperature);
            }
        })
        .map_err(|error| format!("start fan policy loop: {error}"))?;
    thread::Builder::new()
        .name("macluster-fan-control-socket".into())
        .spawn(move || serve(listener, peer_uid, listener_engine, listener_cache))
        .map_err(|error| format!("start fan control socket: {error}"))?;

    Ok(())
}

fn serve(
    listener: UnixListener,
    peer_uid: libc::uid_t,
    engine: Arc<Mutex<FanEngine>>,
    power_cache: Arc<Mutex<PowerCache>>,
) {
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        if peer_uid_for(&stream).ok() != Some(peer_uid) {
            continue;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let mut line = String::new();
        let read = {
            let limited_stream = (&mut stream).take(4097);
            BufReader::new(limited_stream).read_line(&mut line)
        };
        if read.is_err() || line.len() > 4096 {
            continue;
        }
        let Ok(command) = serde_json::from_str::<FanHelperCommand>(&line) else {
            continue;
        };
        let temperature = power_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .temperature(Instant::now());
        let mut engine = engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = match command {
            FanHelperCommand::Status => Ok(engine.status()),
            FanHelperCommand::Set { policy } => engine.set_policy(policy).map(|()| {
                if policy != FanPolicy::System {
                    engine.tick(temperature);
                }
                engine.status()
            }),
        };
        let (status, error) = match result {
            Ok(status) => (status, None),
            Err(error) => (engine.status(), Some(error)),
        };
        let reply = FanHelperResponse { status, error };
        if let Ok(mut bytes) = serde_json::to_vec(&reply) {
            bytes.push(b'\n');
            let _ = stream.write_all(&bytes);
        }
    }
}

fn peer_uid_for(stream: &UnixStream) -> std::io::Result<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn manual_marker_exists() -> bool {
    std::fs::symlink_metadata(MANUAL_MARKER)
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.uid() == 0)
}

fn create_manual_marker() -> Result<(), String> {
    match std::fs::symlink_metadata(MANUAL_MARKER) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.uid() == 0 => return Ok(()),
        Ok(_) => return Err("manual fan marker path is occupied by an untrusted file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect manual fan marker: {error}")),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(MANUAL_MARKER)
        .map_err(|error| format!("create manual fan marker: {error}"))?;
    Ok(())
}

fn remove_manual_marker() -> Result<(), String> {
    match std::fs::symlink_metadata(MANUAL_MARKER) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.uid() == 0 => {
            std::fs::remove_file(MANUAL_MARKER)
                .map_err(|error| format!("remove manual fan marker: {error}"))
        }
        Ok(_) => Err("refusing to remove an untrusted manual fan marker".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect manual fan marker: {error}")),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct Hardware {
    connection: u32,
    ftst_available: bool,
    ftst_engaged: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Hardware {
    fn open() -> Result<(Self, Vec<FanInfo>), String> {
        use macmon::sources::IOServiceIterator;
        let iterator = IOServiceIterator::new("AppleSMC").map_err(|error| error.to_string())?;
        let mut connection = 0;
        for (service, name) in iterator {
            if name == "AppleSMCKeysEndpoint" {
                let result =
                    unsafe { IOServiceOpen(service, mach_task_self(), 0, &mut connection) };
                unsafe { IOObjectRelease(service) };
                if result == 0 && connection != 0 {
                    break;
                }
            } else {
                unsafe { IOObjectRelease(service) };
            }
        }
        if connection == 0 {
            return Err("AppleSMC fan-control service is unavailable".into());
        }
        let mut hardware = Self {
            connection,
            ftst_available: false,
            ftst_engaged: false,
        };
        let fans = hardware.discover_fans()?;
        if fans.is_empty() {
            return Err("AppleSMC did not report controllable fans".into());
        }
        hardware.ftst_available = hardware.key_info("Ftst").is_ok();
        Ok((hardware, fans))
    }

    fn exchange(
        &self,
        input: &macmon::sources::KeyData,
    ) -> Result<macmon::sources::KeyData, String> {
        use std::mem::size_of;
        let mut output = macmon::sources::KeyData::default();
        let mut output_size = size_of::<macmon::sources::KeyData>();
        let result = unsafe {
            IOConnectCallStructMethod(
                self.connection,
                2,
                input as *const _ as *const std::ffi::c_void,
                size_of::<macmon::sources::KeyData>(),
                &mut output as *mut _ as *mut std::ffi::c_void,
                &mut output_size,
            )
        };
        if result != 0 {
            return Err(format!("AppleSMC request failed ({result})"));
        }
        if output.result != 0 {
            return Err(format!("AppleSMC rejected the request ({})", output.result));
        }
        Ok(output)
    }

    fn key_id(key: &str) -> Result<u32, String> {
        let bytes: [u8; 4] = key
            .as_bytes()
            .try_into()
            .map_err(|_| "SMC keys must be four characters".to_owned())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn key_info(&self, key: &str) -> Result<macmon::sources::KeyInfo, String> {
        let key_id = Self::key_id(key)?;
        let input = macmon::sources::KeyData {
            key: key_id,
            data8: 9,
            ..Default::default()
        };
        Ok(self.exchange(&input)?.key_info)
    }

    fn read(&self, key: &str) -> Result<(macmon::sources::KeyInfo, Vec<u8>), String> {
        let key_id = Self::key_id(key)?;
        let info = self.key_info(key)?;
        if info.data_size == 0 || info.data_size > 32 {
            return Err(format!("invalid AppleSMC value size for {key}"));
        }
        let input = macmon::sources::KeyData {
            key: key_id,
            key_info: info,
            data8: 5,
            ..Default::default()
        };
        let output = self.exchange(&input)?;
        Ok((info, output.bytes[..info.data_size as usize].to_vec()))
    }

    fn write(&self, key: &str, bytes: &[u8]) -> Result<(), String> {
        let key_id = Self::key_id(key)?;
        let info = self.key_info(key)?;
        if info.data_size as usize != bytes.len() {
            return Err(format!("unexpected AppleSMC value size for {key}"));
        }
        let mut input = macmon::sources::KeyData {
            key: key_id,
            key_info: info,
            data8: 6,
            ..Default::default()
        };
        input.bytes[..bytes.len()].copy_from_slice(bytes);
        self.exchange(&input).map(|_| ())
    }

    fn numeric(&self, key: &str) -> Result<u32, String> {
        let (info, bytes) = self.read(key)?;
        let kind = info.data_type.to_be_bytes();
        let value = match (&kind, bytes.as_slice()) {
            (b"flt ", [a, b, c, d]) => f32::from_le_bytes([*a, *b, *c, *d]),
            (b"fpe2", [a, b, ..]) => (((*a as u16) << 6) | ((*b as u16) >> 2)) as f32,
            (b"ui8 ", [a, ..]) => *a as f32,
            (b"ui16", [a, b, ..]) => u16::from_be_bytes([*a, *b]) as f32,
            (b"ui32", [a, b, c, d, ..]) => u32::from_be_bytes([*a, *b, *c, *d]) as f32,
            _ => return Err(format!("unsupported AppleSMC value type for {key}")),
        };
        if !value.is_finite() || !(0.0..=100_000.0).contains(&value) {
            return Err(format!("invalid AppleSMC reading for {key}"));
        }
        Ok(value.round() as u32)
    }

    fn discover_fans(&self) -> Result<Vec<FanInfo>, String> {
        let count = self.numeric("FNum")?.min(16) as u8;
        let mut fans = Vec::new();
        for index in 0..count {
            let mode_key = [format!("F{index}Md"), format!("F{index}md")]
                .into_iter()
                .find(|key| {
                    self.key_info(key).is_ok_and(|info| {
                        info.data_size == 1 && info.data_type.to_be_bytes() == *b"ui8 "
                    })
                });
            let (Some(mode_key), Some(min_rpm), Some(max_rpm)) = (
                mode_key,
                self.numeric(&format!("F{index}Mn")).ok(),
                self.numeric(&format!("F{index}Mx")).ok(),
            ) else {
                continue;
            };
            let target_key = format!("F{index}Tg");
            let target_is_float = self
                .key_info(&target_key)
                .is_ok_and(|info| info.data_size == 4 && info.data_type.to_be_bytes() == *b"flt ");
            if max_rpm > 0 && max_rpm >= min_rpm && target_is_float {
                fans.push(FanInfo {
                    mode_key,
                    target_key,
                    min_rpm,
                    max_rpm,
                });
            }
        }
        Ok(fans)
    }

    fn write_u8(&self, key: &str, value: u8) -> Result<(), String> {
        let info = self.key_info(key)?;
        if info.data_size != 1 || info.data_type.to_be_bytes() != *b"ui8 " {
            return Err(format!("unexpected AppleSMC value type for {key}"));
        }
        self.write(key, &[value])
    }

    fn write_mode(&mut self, fan: &FanInfo, mode: u8) -> Result<(), String> {
        match self.write_u8(&fan.mode_key, mode) {
            Ok(()) => Ok(()),
            Err(first_error) if mode == 1 && fan.mode_key.ends_with("Md") => {
                // Recent Apple Silicon firmware can reserve manual writes for
                // thermalmonitord. Try its documented research unlock only
                // after a normal write is rejected, with a six-second retry cap.
                self.write_u8("Ftst", 1).map_err(|_| first_error.clone())?;
                self.ftst_engaged = true;
                let mut last_error = first_error;
                for _ in 0..60 {
                    thread::sleep(Duration::from_millis(100));
                    match self.write_u8(&fan.mode_key, mode) {
                        Ok(()) => return Ok(()),
                        Err(error) => last_error = error,
                    }
                }
                Err(last_error)
            }
            Err(error) => Err(error),
        }
    }

    fn set_targets(&mut self, fans: &[FanInfo], targets: &[u32]) -> Result<(), String> {
        if fans.len() != targets.len() {
            return Err("fan target count mismatch".into());
        }
        for (fan, rpm) in fans.iter().zip(targets) {
            self.write_mode(fan, 1)?;
            self.write(&fan.target_key, &(*rpm as f32).to_le_bytes())?;
        }
        Ok(())
    }

    fn manual_mode_lost(&self, fans: &[FanInfo]) -> Result<bool, String> {
        for fan in fans {
            if self.numeric(&fan.mode_key)? != 1 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn restore_system(&mut self, fans: &[FanInfo]) -> Result<(), String> {
        let mut first_error = None;
        for fan in fans {
            if let Err(error) = self.write_u8(&fan.mode_key, 0) {
                first_error.get_or_insert(error);
            }
        }
        if first_error.is_none() && self.ftst_engaged {
            match self.write_u8("Ftst", 0) {
                Ok(()) => self.ftst_engaged = false,
                Err(error) => first_error = Some(error),
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for Hardware {
    fn drop(&mut self) {
        unsafe {
            IOServiceClose(self.connection);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn IOServiceOpen(service: u32, task: u32, kind: u32, connection: *mut u32) -> i32;
    fn IOServiceClose(connection: u32) -> i32;
    fn IOObjectRelease(object: u32) -> u32;
    fn IOConnectCallStructMethod(
        connection: u32,
        selector: u32,
        input: *const std::ffi::c_void,
        input_size: usize,
        output: *mut std::ffi::c_void,
        output_size: *mut usize,
    ) -> i32;
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
struct Hardware;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl Hardware {
    fn open() -> Result<(Self, Vec<FanInfo>), String> {
        Err("fan control is currently supported only on Apple Silicon Macs".into())
    }
    fn set_targets(&mut self, _fans: &[FanInfo], _targets: &[u32]) -> Result<(), String> {
        Err("fan control is unavailable on this platform".into())
    }
    fn restore_system(&mut self, _fans: &[FanInfo]) -> Result<(), String> {
        Ok(())
    }
    fn manual_mode_lost(&self, _fans: &[FanInfo]) -> Result<bool, String> {
        Ok(false)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const _: [(); 80] = [(); std::mem::size_of::<macmon::sources::KeyData>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arming_uses_fresh_cold_temperature_without_hardware_writes() {
        let mut engine = FanEngine::unsupported("test");
        engine.supported = true;
        engine.arm_curve(FanPolicy::Auto);
        assert!(engine.message.as_deref().unwrap().contains("fresh CPU"));
        engine.tick(Some(35.0));
        let status = engine.status();
        assert_eq!(status.average_temperature_deci_celsius, Some(350));
        assert!(!status.active);
        assert!(status.message.unwrap().contains("below 40"));
    }

    #[test]
    fn repeated_policy_preserves_samples_and_curve_switch_preserves_manual_ownership() {
        let mut engine = FanEngine::unsupported("test");
        engine.arm_curve(FanPolicy::Auto);
        engine.active = true;
        engine.target_rpm = Some(2000);
        engine.last_targets = vec![2000];
        engine.temperatures.push_back(55.0);
        engine.arm_curve(FanPolicy::Auto);
        assert_eq!(engine.temperatures.len(), 1);
        engine.arm_curve(FanPolicy::Power);
        assert!(engine.active);
        assert_eq!(engine.target_rpm, Some(2000));
        assert_eq!(engine.last_targets, vec![2000]);
    }
}
