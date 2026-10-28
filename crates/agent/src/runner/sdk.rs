//! Translate unavailable login-Mac SDK references to the worker's selected SDK.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(super) fn environment_overrides(
    environment: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    if !cfg!(target_os = "macos") {
        return Ok(BTreeMap::new());
    }
    overrides_with(
        environment,
        |path| Path::new(path).is_dir(),
        resolve_local_sdk,
    )
}

fn build_variable(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    super::is_toolchain_cache_variable(key)
        || [
            "CFLAGS",
            "CXXFLAGS",
            "CPPFLAGS",
            "LDFLAGS",
            "FFLAGS",
            "FCFLAGS",
            "OBJCFLAGS",
            "OBJCXXFLAGS",
        ]
        .iter()
        .any(|flag| upper.ends_with(&format!("_{flag}")))
        || [
            "CFLAGS_",
            "CXXFLAGS_",
            "CPPFLAGS_",
            "LDFLAGS_",
            "FFLAGS_",
            "FCFLAGS_",
            "OBJCFLAGS_",
            "OBJCXXFLAGS_",
            "BINDGEN_EXTRA_CLANG_ARGS",
        ]
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

fn sdk_roots(value: &str) -> Vec<(usize, &str)> {
    let mut roots = Vec::new();
    for (start, _) in value
        .match_indices("/Applications/")
        .chain(value.match_indices("/Library/Developer/CommandLineTools/"))
    {
        let tail = &value[start..];
        let marker = if tail.starts_with("/Applications/") {
            "/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX"
        } else {
            "/SDKs/MacOSX"
        };
        let Some(position) = tail.find(marker) else {
            continue;
        };
        let prefix = &tail[..position];
        if tail.starts_with("/Applications/") {
            if !prefix.ends_with(".app")
                || prefix.matches("/Applications/").count() != 1
                || prefix.contains(['\'', '"', '=', '\n', '\r', '\t', '\u{1f}'])
            {
                continue;
            }
        } else if prefix != "/Library/Developer/CommandLineTools" {
            continue;
        }
        let version_start = position + marker.len();
        let Some(suffix) = tail[version_start..].find(".sdk") else {
            continue;
        };
        let version = &tail[version_start..version_start + suffix];
        if !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            continue;
        }
        let end = version_start + suffix + ".sdk".len();
        if tail
            .as_bytes()
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            continue;
        }
        roots.push((start, &tail[..end]));
    }
    roots.sort_by_key(|(start, _)| *start);
    roots
}

fn apple_developer_root(value: &str) -> bool {
    value == "/Library/Developer/CommandLineTools"
        || value.starts_with("/Applications/") && value.ends_with(".app/Contents/Developer")
}

fn developer_root(sdk: &str) -> Option<&str> {
    sdk.find("/Platforms/MacOSX.platform/")
        .or_else(|| sdk.find("/SDKs/MacOSX"))
        .map(|position| &sdk[..position])
}

fn overrides_with(
    environment: &BTreeMap<String, String>,
    exists: impl Fn(&str) -> bool,
    resolve: impl FnOnce() -> Result<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let missing: BTreeSet<_> = environment
        .iter()
        .filter(|(key, _)| build_variable(key))
        .flat_map(|(_, value)| sdk_roots(value).into_iter().map(|(_, root)| root))
        .filter(|root| !exists(root))
        .collect();
    let developer_missing = environment
        .get("DEVELOPER_DIR")
        .is_some_and(|value| apple_developer_root(value) && !exists(value));
    if missing.is_empty() && !developer_missing {
        return Ok(BTreeMap::new());
    }

    let existing_sdk = environment
        .get("SDKROOT")
        .filter(|value| !value.is_empty() && exists(value));
    let detected_sdk = if existing_sdk.is_none() || developer_missing {
        Some(resolve().map_err(|error| format!("cannot resolve the compute node's macOS SDK: {error}; install/select Xcode Command Line Tools on that node with `xcode-select --install`"))?)
    } else {
        None
    };
    let replacement = existing_sdk
        .map(String::as_str)
        .or(detected_sdk.as_deref())
        .ok_or_else(|| "no usable macOS SDK was selected".to_owned())?;
    let mut changes = BTreeMap::new();
    for (key, value) in environment.iter().filter(|(key, _)| build_variable(key)) {
        let mut adapted = String::new();
        let mut cursor = 0;
        for (start, root) in sdk_roots(value) {
            if !missing.contains(root) {
                continue;
            }
            adapted.push_str(&value[cursor..start]);
            adapted.push_str(replacement);
            cursor = start + root.len();
        }
        if cursor > 0 {
            adapted.push_str(&value[cursor..]);
            changes.insert(key.clone(), adapted);
        }
    }
    if !missing.is_empty() && environment.get("SDKROOT").is_none_or(String::is_empty) {
        changes.insert("SDKROOT".into(), replacement.into());
    }
    if developer_missing {
        let local = detected_sdk
            .as_deref()
            .and_then(developer_root)
            .ok_or_else(|| {
                "cannot derive the local Apple developer directory from its SDK".to_owned()
            })?;
        changes.insert("DEVELOPER_DIR".into(), local.into());
    }
    Ok(changes)
}

fn resolve_local_sdk() -> Result<String, String> {
    use std::{
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let mut child = Command::new("/usr/bin/xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("xcrun SDK lookup timed out after 5 seconds".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let sdk = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let sdk = sdk.trim();
    if !output.status.success()
        || !Path::new(sdk).is_absolute()
        || !Path::new(sdk).join("usr/include/stdlib.h").is_file()
    {
        return Err("xcrun did not return an installed macOS SDK with system headers".into());
    }
    Path::new(sdk)
        .canonicalize()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("cannot resolve the selected SDK directory: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const OLD: &str = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";
    const LOCAL: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";

    #[test]
    fn missing_sdk_is_replaced_consistently_without_changing_compilers() {
        let env = BTreeMap::from([
            ("SDKROOT".into(), OLD.into()),
            ("CONDA_BUILD_SYSROOT".into(), OLD.into()),
            ("CMAKE_OSX_SYSROOT".into(), OLD.into()),
            (
                "CMAKE_ARGS".into(),
                format!("-DCMAKE_OSX_SYSROOT='{OLD}' -DCMAKE_BUILD_TYPE=Release"),
            ),
            (
                "CFLAGS".into(),
                format!("-O2 -isysroot '{OLD}' -I/shared/include"),
            ),
            (
                "CXXFLAGS_aarch64_apple_darwin".into(),
                format!("--sysroot={OLD}"),
            ),
            (
                "CARGO_ENCODED_RUSTFLAGS".into(),
                format!("-C\u{1f}link-arg=-isysroot\u{1f}-C\u{1f}link-arg={OLD}"),
            ),
            ("CC".into(), "/shared/mamba/bin/clang".into()),
            ("NOTES".into(), OLD.into()),
        ]);
        let changes = overrides_with(&env, |_| false, || Ok(LOCAL.into())).unwrap();
        for key in ["SDKROOT", "CONDA_BUILD_SYSROOT", "CMAKE_OSX_SYSROOT"] {
            assert_eq!(changes[key], LOCAL);
        }
        assert_eq!(
            changes["CFLAGS"],
            format!("-O2 -isysroot '{LOCAL}' -I/shared/include")
        );
        assert_eq!(
            changes["CMAKE_ARGS"],
            format!("-DCMAKE_OSX_SYSROOT='{LOCAL}' -DCMAKE_BUILD_TYPE=Release")
        );
        assert_eq!(
            changes["CXXFLAGS_aarch64_apple_darwin"],
            format!("--sysroot={LOCAL}")
        );
        assert!(changes["CARGO_ENCODED_RUSTFLAGS"].ends_with(LOCAL));
        assert!(!changes.contains_key("CC"));
        assert!(!changes.contains_key("NOTES"));
    }

    #[test]
    fn valid_or_custom_sdk_and_unrelated_environments_do_not_trigger_detection() {
        for env in [
            BTreeMap::new(),
            BTreeMap::from([("SDKROOT".into(), OLD.into())]),
            BTreeMap::from([("SDKROOT".into(), "/shared/custom/MacOSX.sdk".into())]),
            BTreeMap::from([("CFLAGS".into(), "--sysroot=/shared/linux-sdk".into())]),
            BTreeMap::from([("SDKROOT".into(), "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk".into())]),
        ] {
            assert!(overrides_with(&env, |path| path == OLD, || panic!("unnecessary SDK probe")).unwrap().is_empty());
        }
    }

    #[test]
    fn versioned_sdk_paths_and_header_subpaths_preserve_suffixes() {
        let old = OLD
            .replace("Xcode.app", "Xcode 27.app")
            .replace("MacOSX.sdk", "MacOSX27.0.sdk");
        let env = BTreeMap::from([(
            "CPPFLAGS".into(),
            format!("-isystem '{old}/usr/include' -L/shared/lib"),
        )]);
        let changes = overrides_with(&env, |_| false, || Ok(LOCAL.into())).unwrap();
        assert_eq!(
            changes["CPPFLAGS"],
            format!("-isystem '{LOCAL}/usr/include' -L/shared/lib")
        );
        assert_eq!(changes["SDKROOT"], LOCAL);
    }

    #[test]
    fn preserves_existing_sdk_selection_when_replacing_other_missing_references() {
        let env = BTreeMap::from([
            ("SDKROOT".into(), "/shared/pinned-sdk".into()),
            ("CMAKE_ARGS".into(), format!("-DCMAKE_OSX_SYSROOT={OLD}")),
        ]);
        let changes = overrides_with(
            &env,
            |path| path == "/shared/pinned-sdk",
            || panic!("valid selected SDK is sufficient"),
        )
        .unwrap();
        assert_eq!(
            changes["CMAKE_ARGS"],
            "-DCMAKE_OSX_SYSROOT=/shared/pinned-sdk"
        );
        assert!(!changes.contains_key("SDKROOT"));
    }

    #[test]
    fn missing_developer_directory_is_mapped_to_local_tools() {
        let env = BTreeMap::from([(
            "DEVELOPER_DIR".into(),
            "/Applications/Xcode.app/Contents/Developer".into(),
        )]);
        let changes = overrides_with(&env, |_| false, || Ok(LOCAL.into())).unwrap();
        assert_eq!(
            changes["DEVELOPER_DIR"],
            "/Library/Developer/CommandLineTools"
        );
    }

    #[test]
    fn sdk_rewrite_preserves_other_tools_and_similar_path_names() {
        let other = "/Applications/Xcode.app/Contents/Developer/usr/bin/make";
        let text = format!("-DMAKE={other} -DSDK={OLD} -DBACKUP={OLD}.backup");
        let env = BTreeMap::from([("CMAKE_ARGS".into(), text)]);
        let changes = overrides_with(&env, |_| false, || Ok(LOCAL.into())).unwrap();
        assert_eq!(
            changes["CMAKE_ARGS"],
            format!("-DMAKE={other} -DSDK={LOCAL} -DBACKUP={OLD}.backup")
        );
    }

    #[test]
    fn missing_local_sdk_reports_actionable_error() {
        let env = BTreeMap::from([("SDKROOT".into(), OLD.into())]);
        let error =
            overrides_with(&env, |_| false, || Err("no selected macOS SDK".into())).unwrap_err();
        assert!(error.contains("SDK"));
    }
}
