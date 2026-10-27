use std::{env, path::PathBuf, process::Command};

fn main() {
    let workspace = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../..")
        .canonicalize()
        .expect("workspace directory must exist");
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/power-helper/Cargo.toml",
        "crates/power-helper/src",
    ] {
        println!("cargo:rerun-if-changed={}", workspace.join(path).display());
    }
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let output_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("power-helper");
    // The child builds only the helper, which does not depend on the CLI.
    // Separate target directories avoid the outer Cargo build lock. Do not
    // inherit its jobserver while its build-script job is waiting on us.
    let output = Command::new(env::var_os("CARGO").unwrap())
        .current_dir(&workspace)
        .args([
            "build",
            "--locked",
            "--release",
            "--jobs=1",
            "--package=macluster-power-helper",
            "--bin=macluster-power",
            "--target",
            &target,
            "--target-dir",
        ])
        .arg(&output_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("MAKEFLAGS")
        .env_remove("MFLAGS")
        .output()
        .expect("could not invoke Cargo to build embedded power helper");
    assert!(
        output.status.success(),
        "could not build embedded macluster-power for {target}:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let helper = output_dir.join(target).join("release/macluster-power");
    assert!(helper.is_file(), "helper artifact is missing");
    println!(
        "cargo:rustc-env=MACLUSTER_EMBEDDED_POWER={}",
        helper.display()
    );
}
