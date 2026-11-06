use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let workspace = manifest
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    println!(
        "cargo:rerun-if-changed={}",
        workspace.join("crates").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace.join("Cargo.lock").display()
    );

    let version = env::var("CARGO_PKG_VERSION").expect("package version");
    let build_id = source_build_id(&workspace, &version);
    println!("cargo:rustc-env=MACLUSTER_BUILD_ID={build_id}");
}

fn source_build_id(workspace: &Path, version: &str) -> String {
    let files = tracked_source_files(workspace).unwrap_or_else(|| source_files(workspace));
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    hash_bytes(&mut hash, version.as_bytes());
    for file in files {
        let Ok(relative) = file.strip_prefix(workspace) else {
            continue;
        };
        let Ok(contents) = fs::read(&file) else {
            continue;
        };
        hash_bytes(&mut hash, relative.to_string_lossy().as_bytes());
        hash_bytes(&mut hash, &contents);
    }
    format!("{version}-src-{hash:016x}")
}

fn tracked_source_files(workspace: &Path) -> Option<Vec<PathBuf>> {
    let output = Command::new("git")
        .current_dir(workspace)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut files = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .filter_map(|path| std::str::from_utf8(path).ok())
        .filter(|path| source_relevant(path))
        .map(|path| workspace.join(path))
        .collect::<Vec<_>>();
    files.sort();
    Some(files)
}

fn source_files(workspace: &Path) -> Vec<PathBuf> {
    let mut pending = vec![workspace.join("crates")];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .strip_prefix(workspace)
                .ok()
                .and_then(|relative| relative.to_str())
                .is_some_and(source_relevant)
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn source_relevant(path: &str) -> bool {
    let path = Path::new(path);
    if !path.starts_with("crates")
        && path != Path::new("Cargo.toml")
        && path != Path::new("Cargo.lock")
    {
        return false;
    }
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("rs" | "toml" | "lock" | "c" | "h" | "html" | "js" | "css")
    )
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    *hash ^= 0xff;
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}
