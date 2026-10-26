fn main() {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "macluster".into());
    let args: Vec<String> = args.collect();
    std::process::exit(macluster_cli::run_with(&program, &args));
}
