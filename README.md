# macluster

Run jobs across a small group of Macs. Written in Rust, with SSH for node access and NFS for shared files.

English · [简体中文](doc/README.zh-CN.md)

## How it works

- The **login Mac** runs the controller and accepts submissions. It also hosts shared storage by default.
- **Compute Macs** run the jobs. Each Mac runs one job at a time, with no CPU-core or memory quota.
- Projects, software environments, and results are shared through NFS.
- The login Mac stays outside compute queues. You can choose a separate Mac for storage.

This is an early-stage project for home and lab clusters.

## Requirements

- macOS 12 or newer.
- Rust 1.90 or newer to build the application.
- Remote Login enabled on compute Macs, with SSH access from the login Mac.
- Accounts and file permissions that allow NFS clients to read and write shared files.
- Shared directories on volumes that support macOS NFS export, such as APFS. ExFAT volumes cannot be exported.

Setup may ask for administrator authorization on each affected Mac. Use a binary built for that Mac's CPU architecture.

For protected folders or external volumes, the storage Mac may also require **System Settings → Privacy & Security → Full Disk Access** for `/sbin/nfsd`. After granting access, run `sudo /sbin/nfsd restart` on that Mac and retry enrollment.

## Install

Run on the login Mac, from this repository:

~~~sh
cargo build --release --locked --workspace
packaging/scripts/install-user.sh
~~~

The installer places the application, power helper, and command aliases in `~/.local/bin`. Add it to your shell's `PATH`:

~~~sh
export PATH="$HOME/.local/bin:$PATH"
~~~

Add that line to your shell configuration to keep it after reopening Terminal. Rust and Python are not needed to run the installed application.

## Create a cluster

Initialize on the login Mac:

~~~sh
macluster init --name home --queue mini01 --shared-root /Users/Shared/macluster
~~~

Add a compute Mac. Replace the sample SSH user and IP address with your own:

~~~sh
mnode -a cluster-user@192.0.2.10
mnode -l
~~~

Enrollment installs the Agent, writes its configuration, and sets up shared storage. If needed, it helps you verify the SSH host key and install an SSH key. The SSH login password and each Mac's administrator password are separate.

Start the controller and leave it running:

~~~sh
macluster controller run
~~~

Use another Terminal window to submit jobs.

## Run jobs

~~~sh
# Submit a command or a script.
msub -q mini01 hostname
msub -q mini01 job.sh

# Run an attached command, or open an interactive shell.
msub -Is python --version
msub -Is

# Inspect jobs and queues.
mjob
mqueue

# Read output or cancel a job. Replace 1 with the submitted job ID.
mjob --log 1
mkill 1
~~~

Quote commands that contain shell operators so the allocated Mac executes them:

~~~sh
msub --wrap 'python analysis.py > analysis.log 2>&1'
~~~

Commands submitted from a shared directory run in that directory. From outside all shares, inline commands use the primary shared root. Use `--cwd PATH` to choose a shared working directory.

Relative files written by a task appear in its working directory. Default logs are copied to the primary share after the task exits.

## Share projects and tools

Add another shared directory:

~~~sh
mnode -a local:~/projects/example --share-id project \
  --mount-root /Users/Shared/macluster-shares/project
~~~

To share a Python environment, Homebrew, or a compiler, register its directory too. `init` offers detected software directories during setup.

For example, share a Mamba installation at its original path:

~~~sh
mnode -a "local:$HOME/mamba" --share-id mamba --mount-root "$HOME/mamba"
~~~

Then activate an environment in the login terminal and submit from a shared project directory:

~~~sh
msub -Is python --version
msub -Is pip install . --break-system-packages
~~~

`msub` forwards exported environment variables, including the active Python environment. The software files must also be shared, and active environments must resolve at the same absolute path on every node. An unshared environment is rejected.

Shell aliases and functions are not forwarded. Environment variables are saved with the job, so avoid exporting secrets to tasks.

## Monitor the cluster

~~~sh
mtop
mtop --once
~~~

`mtop` shows jobs, CPU, memory, disk I/O, network, and available GPU, temperature, fan, and power readings.

Use arrows or `j`/`k` to select a node, Enter for its processes, and `q` to quit. In process details, `c` sorts by CPU and `m` by memory.

CPU usage can exceed 100%: an eight-logical-CPU Mac can reach 800%. Unavailable hardware readings show `N/A`.

## Maintain the cluster

| Command | Action |
| --- | --- |
| `mnode -l` | Show nodes and their NFS paths. |
| `mnode -rm NODE_ID` | Remove an idle node that does not host a share. |
| `macluster init` | Ask to reset the current cluster, then configure a new one. |
| `macluster init --force` | Allow reset to abandon unsynchronized output from finished jobs. Active jobs still block reset. |

Reset preserves shared data files and archives old configuration and job state.

Node or share changes may ask to stop the controller. Follow the command's restart instructions afterward. Known Agent version/hash differences trigger an automatic update before an operation.

For a separate storage Mac, initialize with `--primary-nfs`:

~~~sh
macluster init --name home --queue mini01 \
  --primary-nfs 'storage-user@198.51.100.10:22:/Volumes/Data/macluster' \
  --shared-root /Users/Shared/macluster
mnode -a local
~~~

Replace the example storage account, IP, and directory. The storage Mac also stays outside compute queues.

## Help

Run `macluster --help` or `msub --help` for options.

If a job stays pending, check that the controller is running and its queue has a `READY` compute node. If a tool is missing, check its shared path and the environment in the submitting terminal.

A launchd service template is available at [packaging/launchd/org.macluster.controller.plist](packaging/launchd/org.macluster.controller.plist). Edit its paths before installing it.

## License

[GNU GPL v3 or later](LICENSE) (`GPL-3.0-or-later`). Commercial use is allowed; redistribution must follow the GPL's license and source-code requirements.
