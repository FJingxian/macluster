# macluster

`macluster` is a small Rust job manager for a macOS home cluster. By default,
the login Mac is also the primary NFS server, but it does not accept jobs. The
default compute queue starts empty; add compute Macs with `mnode -a`. An optional
remote macOS storage node can provide the primary NFS directory. The scheduler
runs one macluster job at a time on each compute node; a job can use the whole
node and does not request cores or memory.

## Current implementation

The workspace contains the shared protocol, validated configuration, local
SQLite job store, FIFO whole-node scheduler, SSH transport, detached task
runner, command aliases, and macOS metrics sampler. Jobs and controller state
are stored on the login Mac. Scripts are snapshotted before acceptance; shared
project files, task working directories, and completed output logs use NFS.

Some first-version limits are deliberate:

- `macluster init` creates a first cluster from the login Mac. Use
  `--primary-nfs USER@IPv4[:PORT]:SOURCE_PATH` to choose another Mac as the
  primary storage server; it stays outside compute queues. The login Mac also
  stays outside compute queues. `--shared-root PATH` is the common client mount path.
  When a config already exists, `macluster init` asks whether to reset it,
  removes verified managed mounts and NFS entries, archives old state, and
  continues directly to new cluster setup.
  See [Initialize or rebuild a cluster](#initialize-or-rebuild-a-cluster).
- `mnode -a USER@IPv4[:PORT]` enrolls a node into the default queue after SSH,
  architecture, machine identity, and NFS checks. `mnode -a local` enrolls the
  login Mac without SSH and keeps it outside compute queues; `--queue QUEUE`
  selects another configured queue for an SSH-added compute node.
  A source path plus `--share-id ID` registers an additional NFS share; use
  `mnode -a local` without a source path to mount the configured primary share
  while enrolling the login Mac.
  `mnode -l` lists nodes and share readiness, and `mnode -rm NODE_ID` removes
  an idle node. Add/remove and share setup block new submissions, let the
  controller finish active jobs and output sync, then stop it before changing
  cluster configuration. Run `macluster controller run` after the command
  exits to resume scheduling; queued jobs remain queued during maintenance.
- `init` owns reset-time cleanup of managed NFS exports and mounts. Before a
  user-facing command (`init`, `msub`, `mjob`, `mqueue`, `mkill`, `mtop`, `mnode`, or
  controller command), macluster checks the version/hash of every configured
  Agent. A known mismatch automatically starts the resumable update on all
  nodes; it does not depend on the selected queue. If the controller is
  running, the update asks to stop it only after jobs and output sync have
  drained. Restart the controller and retry the requested command if the
  update stopped it. Internal Agent RPCs, the unimplemented `agent` command, and help bypass this check; `mnode` and `init`
  can enter recovery when an unfinished node operation blocks the updater.
- Each node runs at most one managed job. The scheduler does not enforce a CPU
  quota, core affinity, or memory limit.
- Inline `msub` commands keep the current directory when it is under the primary
  or a named share; from outside all shares they default to the primary root.
  Use `--cwd PATH` to select a different shared working directory. Server source
  paths are translated to the corresponding client mount path. Script submissions
  require a working directory inside one of the configured shares.
- `mjob --log` reads the shared log copy. After a task exits, an independent
  background worker publishes its retained logs; the node stays reserved until
  publication succeeds. Status probes schedule retries at least five seconds
  apart and do not wait for NFS log I/O. A publisher with no byte progress for
  60 seconds is terminated and retried; a progressing transfer can take longer.
  The current implementation does not stream live output from a compute node.
- `mtop` uses a full-screen terminal view when both input and output are TTYs
  and `TERM` is not `dumb`; it refreshes in place every two seconds. Use
  `q`/Ctrl-C to exit, arrows or `j`/`k` to select, `Enter` for node details,
  `c`/`m`/`n`/`p` to sort by CPU/memory/network/power, `i` to sort by ID, `r`
  to refresh, and `?` for help. `--once` prints one plain-text snapshot;
  `--json` prints one JSON snapshot; redirected output defaults to one plain
  snapshot. CPU is reported as a percentage of one logical CPU, so an 8-CPU
  Mac can report up to 800%. Stale or unavailable values are marked and left
  out of pool totals; partial coverage is shown. Power reports a scope such as
  `CPU` or `SoC` and its sample age. Unknown-age power is shown with `?` and
  omitted from pool totals; readings older than 15 seconds are marked stale.
  The privileged helper samples in the background and serves its last good
  reading through transient `powermetrics` failures for up to 60 seconds;
  mtop still marks readings older than 15 seconds stale. Power becomes `N/A`
  with a reason when no recent sample exists or the helper is unavailable.
  Press `Enter` on a node to show its process list, sorted by CPU use, with
  PID, CPU%, memory, CPU time, and command. That list refreshes every three
  seconds for the selected node while details are open. In expanded details,
  `c` and `m` sort processes by CPU or memory, both descending; outside details
  those keys continue to sort the node list.
- Controller agent requests, primary-share checks, and snapshot publication
  run in bounded child processes. A kernel NFS call can still stall an
  individual child and delay termination after its timeout. A per-job lock
  prevents a blocked log publisher from accumulating duplicate NFS operations;
  Status continues to report local execution state independently of log I/O.
- `msub` forwards the submitting process's exported environment by default,
  including `PATH` and mamba/Conda activation variables. A nonempty active
  `VIRTUAL_ENV` or `CONDA_PREFIX` must be inside a registered share mounted at
  the same absolute path on every node. Its `bin/` is put first in task PATH;
  when both variables are present, the order in submitted PATH selects the
  active environment. `--env KEY=VALUE` overrides individual values. An
  explicit `--env PATH=...` remains authoritative after shared-path filtering.
  Node-local identity, working-directory, temporary-directory, and SSH-agent
  values are not copied. Known path variables are translated from a local NFS
  source to the client mount path. Unshared active environments fail before
  submission instead of silently selecting a compute-local tool. Environment
  values are stored with the job; do not export secrets you do not want
  available to the task.
- Tasks run as the SSH account on the compute Mac. Forwarding environment
  variables does not copy software: each executable must exist on the allocated
  node, either at the same path or on a registered NFS share. Batch and wrapped
  commands do not load shell startup files.

The checked-in launchd file is a template. No live NFS export, mount, SSH
setting, or launchd service is changed by building this repository.

## Build and install the command aliases

Build on macOS with the installed Rust stable toolchain:

```sh
cargo build --release --locked --workspace
packaging/scripts/install-user.sh
```

This installs `macluster`, `msub`, `mjob`, `mqueue`, `mkill`, `mtop`,
and `mnode` into `~/.local/bin`. Add that directory to `PATH` if it is not already there. On a
future compute Mac, install the same compatible binary at the path configured
by `remote_binary` (the example uses `/usr/local/bin/macluster`). The binary
does not need Rust or Python at runtime. Cargo targets macOS 12.0 or newer and
the current build uses macOS system SQLite and Apple system frameworks/libraries.
The default build is for the build machine's architecture. To produce the
separate Intel executable from Apple Silicon, build with
`--target x86_64-apple-darwin`; the outputs are not a universal binary.

## Initialize or rebuild a cluster

Run `macluster init` on the Mac that will be the login node. By default, it
stores shared files on that Mac and creates an empty default compute queue. Add
one or more compute Macs afterward. The command prompts for a cluster name,
queue, and shared root; options can be supplied up front:

```sh
macluster init --name home --queue mini01 \
  --shared-root /Users/Shared/macluster
```

To put the primary NFS source on a different Mac, pass its SSH endpoint and
server-side directory. Every client still uses the same `--shared-root` mount
path; the storage Mac is registered for storage and is left out of compute
queues:

```sh
macluster init \
  --primary-nfs 'operator@192.0.2.1:22:/Volumes/Storage/macluster' \
  --shared-root /Users/Shared/macluster
```

The SSH host key must already be trusted and key-based SSH must work. The
storage Mac must run macOS and use a matching account UID/GID. `--host IPv4`
selects the login Mac's address when the cluster network is not the default
route. The initializer displays the topology before it changes NFS or writes
the config. An existing cluster is reset only after explicit confirmation.
If first-time local initialization is interrupted, rerun `macluster init`; it
validates its saved config and primary-share marker, then resumes.

To start over, run:

```sh
macluster init
```

When a config exists, init asks `Reset existing cluster ...? (Y/N) [N]`.
Answer `y` or `Y` to reset and continue directly to new cluster setup;
`n`, `N`, or Enter cancels without changing the old cluster.
New topology options such as `--name` and `--shared-root` can be supplied in
the same command. Reset first blocks new
submissions and lets the controller reconcile
running work. Pending jobs and output synchronization must be resolved with
`mjob`/`mkill` before retrying. If a terminal job's output or snapshot sync is
stuck, `macluster init --force` can discard only that terminal job's
pending sync record. The reset still waits for active jobs to end and checks
that each remote agent is idle; a remote pending log is accepted only when its
terminal job ID, node, and start token match the controller record. Output
that never reached shared storage may then be unavailable through the cluster.
The archive records which terminal sync records were abandoned. The old config
and controller database are archived under
`macluster-archive/<timestamp-id>` beside the state directory.
On remote Macs, an old config that still matches the old cluster identity is
moved to a `.macluster-reset-<id>.bak` file beside the original config.

Reset groups privileged NFS cleanup into one administrator session per host.
Before each session it prints the node, account, and operations. Each Mac
authorizes its own administrator account; a valid sudo cache can skip its
password prompt.

Before unmounting or archiving agent state, reset fences background log
publication, stops verified publisher processes, and waits for their file locks
to be released. If an NFS operation cannot be interrupted, reset pauses with
its fence intact; restore connectivity and retry the same reset command.

New submissions store scripts and default logs under
`jobs/<share UUID>/<job ID>/`, so a newly initialized cluster can reuse job
numbers without overwriting files preserved by reset. Existing jobs retain
their original paths. Before an operational command, `macluster` checks every
configured Agent's build hash. If any known mismatch exists, it starts the
all-node updater before the requested module runs, even when the mismatch is
on a node outside the selected queue. An unknown/offline build does not count
as a confirmed mismatch. Active jobs or output sync block maintenance before
a controller-stop prompt. After a controller stop, restart it and retry the
command. `mnode` remains available to resolve an unfinished node
administration operation that would otherwise block updating.

Agents also persist an independent execution receipt before starting user
code. If the main agent state disappears, the controller requests recovery
using the original job identity and token, without submitting the task again.
If both state and receipt are unavailable, the node remains reserved with a
diagnostic until its execution can be verified safely.

After cleanup, init prompts for the new cluster, queue, and shared-root
settings, followed by the new topology confirmation. Old node and named-share
settings are not reused. If new setup is cancelled after cleanup, the old
cluster remains archived and no active config exists; run `macluster init`
again to finish setup.

Reset preserves the contents of shared storage, mountpoint directories, SSH
keys and host keys, Agent binaries, and machine-level power helpers. It removes
only NFS mounts and export entries whose source, destination, UUID, node ID,
and client address match the old config or a matching incomplete setup journal.
This covers the primary share, every named share, managed server aliases, and
their `.macluster-share-id` markers. An incomplete setup whose alias conflicts
with an existing directory or unrelated symlink preserves that path while
reset clears its exact managed exports and markers. After reset, all share
paths must be configured again; the data directories themselves remain.
Hand-written exports and the system
NFS service are left alone. If preflight fails before cleanup starts, the old
config stays active and the controller may need to be restarted after fixing
the reported issue. Once cleanup starts, a journal beside the config keeps the
controller blocked; rerun `macluster init` to resume
it. A force reset keeps its saved force policy on resume, even if the retry
omits `--force`; macluster displays that policy. Do not start the controller
while reset recovery is pending.

## Configure the shared directory and NFS

1. On the Mac mini, create `/Users/Shared/macluster` on its local disk and
   make it writable by the account that will run jobs. The compute agent
   verifies that this storage node uses a local filesystem. `mnode` can create
   the managed NFS export entry when it enrolls a client.
2. Generate one UUID with `uuidgen`. Put it in `share_uuid` in the config below
   and write the same value, followed by a newline, to
   `/Users/Shared/macluster/.macluster-share-id` on the mini. Keep the marker
   and config private to the cluster operator.
3. Run `mnode -a local` on the login Mac. When the NFS server is remote, it
   authorizes the login client IP and mounts the share on the login Mac. When
   the login Mac hosts NFS, it uses its local shared directory. Later
   `mnode -a USER@IPv4[:PORT]` calls configure and mount the same export for
   each compute Mac. The controller and submit command reject a local
   directory that merely happens to have the marker file.
4. Make sure the shared account mapping permits the compute account to read
   scripts and create job output directories. `projects/`, `jobs/`, and the
   default working directory must be inside the shared root.

The storage node itself uses its local directory; it should not mount its own
export over that directory. The login node and later compute nodes use the NFS
mount. The configured path must be identical on every machine.

## SSH and node setup

On the Mac mini, enable Remote Login for the compute account. Install the
binary and the same cluster configuration there. From the login Mac, install
an SSH key and verify the host key interactively before the scheduler uses
SSH. `SshTransport` uses batch mode and OpenSSH host-key checking; it will not
prompt for a password or accept a new host key while dispatching.
Keep non-interactive shell startup files silent; text printed before the
remote bridge starts would corrupt its framed protocol output.

Keep each node's `host` set to its IP address so NFS source checks use the
actual server address. Optional `ssh_user` and `ssh_port` fields select the
remote account and port explicitly; if omitted, OpenSSH uses its normal
configuration. `remote_config` selects a cluster-specific config on the
remote node; older entries without it use `~/.config/macluster/config.toml`.

Copy `config/macluster.example.toml` to `~/.config/macluster/config.toml` on
the login Mac and the compute Mac. Use the same cluster name, share UUID, node
IDs, queue members, and shared path on both machines. Check the `remote_binary`
path on the compute node.

To add another Mac, run `mnode -a USER@IPv4[:PORT]` from Terminal. The command
first tries existing SSH keys. If key login is not set up, OpenSSH shows the
host fingerprint for you to verify, then `mnode` asks for the remote account
password once and installs a dedicated Ed25519 public key. Password
authentication must be enabled for that account. The password is not saved;
later cluster connections use the generated key. Changed host keys are
rejected. Compute nodes join the default queue; use `--queue QUEUE` to select
another configured queue. The command installs the matching local binary,
creates a cluster-specific remote config, checks the platform UUID, and
configures and mounts the primary NFS share. Use
`mnode -a local` to configure the login Mac; it remains outside compute queues.
Enrollment also stages
`macluster-power` and asks for administrator approval when needed to install its
fixed-operation LaunchDaemon. The cluster agent and submitted tasks still run
as the normal cluster account. If power setup is skipped, repeat `mnode -a`
after building and installing the full workspace. To refresh the privileged
power helper on an already enrolled node, install the new workspace binaries
and rerun that node's same `mnode -a` command; macOS may request administrator
approval. Agent updates do not replace this helper. Local enrollment and share
registration reuse the registered local node's active IPv4 address, including
on Macs with multiple interfaces. An explicit `--host IPv4` overrides that
choice. If the registered address is no longer active, reconnect its interface
or explicitly select a new address; the command does not silently switch to
another network. An unregistered Mac with an ambiguous active address still
requires `--host IPv4`. `USER@127.0.0.1` is accepted as a local alias only for
the current user on port 22.

When an enrolled client is not yet authorized, `mnode` preserves existing
`/etc/exports` entries, adds a managed entry for that client's IP, validates
the file with `/sbin/nfsd`, and enables or starts the NFS service on the storage
Mac. It then mounts and checks the shared directory. `/etc/exports` may be
absent before the first client is enrolled. If a custom export for that path
has conflicting options, `mnode` stops and prints the manual repair steps.

An additional named NFS share can be registered by including its source path
and a share ID:

```sh
mnode -a 'operator@192.0.2.1:22:/Users/Shared/tools' --share-id tools
mnode -a 'local:~/share' --share-id data --host 192.168.2.3
mnode -a 'local:/Users/operator/mamba/envs/analysis' --share-id analysis \
  --mount-root /Users/operator/mamba/envs/analysis
```

If the source directory is missing, `mnode` creates it as the server user. Any
existing path components must be real directories without symlinks, and the
resulting source must be on local storage. Paths may be absolute, `./relative`,
or `~/relative`; the latter two resolve under the server user's home directory.
The command does not change existing file ownership. By default, each client
mounts the share at `/Users/Shared/macluster-shares/<ID>`. `--mount-root PATH`
selects a different absolute client path; this is useful for environments whose
scripts use absolute interpreter paths. Mounting an environment at its source
path keeps those paths valid on every node. If the server's source differs from
the selected mount path, `mnode` creates a managed symlink on the server. If the
source and mount paths are identical, the server uses the source directly. When
they differ, each compute node also gets a managed symlink from the original
source path to its NFS mount, so scripts with absolute interpreter paths work
there too. `mnode` refuses to replace files or unrelated links; empty placeholder
directories at the alias path may be removed. Reset removes only these exact
managed links. The share root and its `bin/` directory are added to task `PATH`,
with shared `bin/` paths taking priority when the submitting PATH has not
selected a shared environment. `msub -o` and `-e` may target any registered
shared directory.
Only registered shared directories are visible to compute nodes; adding a
directory to `PATH` does not share its files.

Repeating the same named-share command verifies every client's actual NFS
source and UUID, and restores missing exports, mounts, or server aliases before
reporting success. The configured data source must still exist with its original
UUID; it is not recreated as an empty directory during repair. New registration
checks client mount paths before recording setup or changing exports. Existing
files, unrelated directories, symlinks, and mounts from another source cause an
error without being overwritten. A failed repair remains resumable with the
same command and is not marked ready.

Adding a parent share replaces existing child shares only when they use the
same server and identical relative source/mount mappings. The command first
requires idle agents, records a resumable operation, checks the old mount
sources and UUIDs, and retires exact managed child exports and mounts. Source
files are preserved; only verified aliases and empty client directories are
removed. Unmanaged exports, changed mounts, and local files at a mount point
block migration. Rerun the same command to resume an interrupted migration.
Registering shares does not install or update the privileged power sampler.

For example, share the entire project before submitting an installation:

```sh
macluster mnode -a local:/Users/operator/script/JanusX \
  --share-id JanusX --mount-root /Users/operator/script/JanusX
# Restart the controller after the configuration change.
cd /Users/operator/script/JanusX
macluster msub -Is 'pwd; python -m pip install .'
```

The task executes in the shared project directory. Installation targets the
selected Python environment; share that environment separately if its files
must also be visible on all nodes. Default stdout/stderr logs remain in the
primary share's job directory; files opened by the task with relative paths
are created in its shared working directory.
When enrolling a node, `mnode` labels administrator prompts with the target
Mac and operation. If its SSH key is missing, it first asks once for the
remote account login password to install the key; administrator authorization
is separate. Updating the storage Mac's NFS export may require that Mac's
administrator password. Installing the power sampler and mounting the primary
share are grouped into one administrator session on the new compute Mac, so
that Mac is prompted at most once for those steps. A cached `sudo` authorization
may skip a prompt. Run `mnode` from an interactive Terminal as the normal
cluster account. Passwords are never stored. If an operation is interrupted,
rerun the same command to resume it.

Node setup never stores SSH or sudo passwords and never accepts an unknown
SSH host key automatically. Node IDs are reserved in the local admin journal
and are not reused after a failed setup. The running `macluster` executable
must include the compute Mac's architecture; build and run the matching target
build first when enrolling a different architecture.

After committing a node change locally, `mnode` atomically synchronizes the
updated cluster config to the other enrolled nodes' configured `remote_config`
paths (or their default config path). Each replaced remote config gets a
backup. If a peer is unreachable or the copied file does not verify, the
operation remains `SYNC_PENDING`; rerun the same add command or the same
`mnode -rm NODE_ID` command to resume synchronization. The login-node TOML
remains the scheduler's source of queue membership.

Agent build preflight runs before every operational module, including command
aliases, and before `init` when an existing valid config is present. When any
configured node's known version or hash differs, macluster
automatically updates every configured Agent, including the login Agent while
keeping it outside compute queues. It asks to stop a running controller only
after active jobs and output synchronization have drained. Running jobs are
not killed. If the controller was stopped for the update, start it with
`macluster controller run` and retry the original command. NFS exports and
mounts are reconciled only by `init`/reset. An interrupted update or peer
config sync is resumed by the next operational command.

`mnode -l` reports `READY` only when the remote agent, primary NFS share, and
every configured named share respond with the expected machine identity and
config digest. Each node is followed by its primary and named NFS mappings:
`SOURCE` shows the server address and source directory, and `TARGET` shows the
path used by that node's jobs. `LOCAL`, `ALIAS`, and `MOUNT` distinguish direct
server access, a server-side path alias, and a client NFS mount. Every mapping
has its own `READY`, `PENDING`, or `UNKNOWN` status. Configured paths remain
visible when a node is unreachable or its health cannot verify the current
config; those mappings are `UNKNOWN`.

Add, remove, and named-share operations ask before stopping a
running controller; `n` cancels the operation. Running jobs are not killed, and
maintenance stops if active jobs or output sync remain. Restart the controller
after each maintenance command. `mnode -rm NODE_ID` refuses any primary or
additional NFS share server, jobs that still reference the node, and remote
executions whose state cannot be verified. It detaches the node from queues
before removing its config and deletes only exact NFS export entries previously
marked as managed by macluster. Operator-managed exports remain unchanged and
are reported. The command does not unmount NFS or delete remote files. For an ID shown as
`SETUP_PENDING` but not yet present in the cluster config, `mnode -rm NODE_ID`
cancels the enrollment, removes only its marked NFS export if one was created,
and permanently reserves the ID.

## Run the controller

For a foreground run while setting up the cluster:

```sh
macluster --config ~/.config/macluster/config.toml \
  --state-dir "$HOME/Library/Application Support/macluster/controller" \
  controller run
```

The controller must stay running to dispatch queued jobs and reconcile node
state. The checked-in template at
`packaging/launchd/org.macluster.controller.plist` can be copied to
`~/Library/LaunchAgents/` after replacing `REPLACE` with the account's home
path and creating the log directory. Review the configuration and state paths
before loading the template with `launchctl`. The SSH agent bridge is started
per SSH request; no separate compute-node daemon is needed. A task runner
detaches from that SSH request and continues if the connection closes.

## Submit and inspect work

```sh
msub -q mini01 job.sh
msub -q mini01 --node mini01-a -J analysis -t 02:00:00 job.sh
msub -q mini01 'pwd'
msub -Is pip install . --break-system-packages
msub -q mini01 --wrap 'python analysis.py --input data.tsv'
msub -Is -q mini01
msub -Is -q mini01 'python -i'

mjob
mjob 1001
mjob --all
mjob --state running
mjob --log 1001
mjob --log 1001 --stderr
mjob --log 1001 --follow
mjob --request-id 5b917843-7b08-4b84-8a35-8fb8495ea0fb

mqueue
mqueue -q mini01 --jobs
mqueue --watch 2

mkill 1001
mkill --force 1001

mtop
mtop -q mini01 --once
mtop --json
```

`msub` accepts `-q/--queue`, `--node`, `-J/--name`, `-t/--time HH:MM:SS`,
`--cwd`, `-o/--output`, `-e/--error`, repeated `--env KEY=VALUE`,
`--request-id UUID`, `--wrap COMMAND`, or `-Is` for an attached interactive
session. With `-Is`, omit the command to open a login interactive shell on the
allocated node, or provide a script/command such as `python -i` to run it in a
remote PTY. Interactive submission requires terminal stdin and stdout. The
target nodes must advertise PTY support. Agent build preflight runs before
submission along with every other operational command. Ctrl-C while waiting cancels the job;
after attachment it is sent to the foreground process. A single non-file command such as
`msub -q mini01 'pwd'` is also accepted as an inline shell command. Multiple
unquoted tokens are passed as safely quoted argv, so flags after the command
name belong to the task: `msub -Is pip install . --break-system-packages`.
Quote a whole command or use `--wrap` for shell operators such as `;`, `>`, and
`|`. Global options such as `--config` and `--state-dir` must appear before the
task command. It also reads leading `#MSUB`
directives for queue, node, name, time, cwd, output, and error. A script's
working directory must be on the primary or a named share. The script is snapshotted; other
input files remain live shared files. Core and memory request flags are
rejected because allocation is whole-node. Save the printed request ID when a
submit result is uncertain; `msub --request-id UUID` replays the cached
submission and `mjob --request-id UUID` looks up its result.

The submitting process's exported environment is included in the job by
default. Init offers detected Mamba/Conda, virtualenv, and Homebrew roots as
named NFS shares, then allows any number of additional software or compiler
roots. Each root is mounted at the same absolute path on every node. You can
also add roots later with `mnode -a local:PATH --share-id ID --mount-root PATH`.
The active `VIRTUAL_ENV` or `CONDA_PREFIX` is selected from the login PATH;
its `bin` is placed first. Shared `CC`, `CXX`, Rust tool, CMake compiler,
pkg-config, SDK, include/library search, and compiler/linker flag paths are
remapped to their compute-visible shares. Absolute build-tool paths outside a
registered share fail at submission with the path that needs to be shared.
For example, once the environment and toolchain roots are shared,
`msub -Is python --version` and `msub -Is pip install .
--break-system-packages` use the login node's exported tools without per-node
shell configuration. Use `--env KEY=VALUE` to override a value for one job.
An explicit `--env PATH=...` is respected after filtering. Batch and wrapped
tasks do not source shell startup files or inherit shell aliases/functions.
Compute-local `HOME`, temporary directories, and SSH-agent values remain local
to the execution node.

When `CARGO_TARGET_DIR` is unset, empty, or inherited from an unshared login
path, each compute node uses a reusable private cache under its own temporary
directory, separated by cluster, project, and build toolchain. `CARGO_HOME`
defaults to a private node-local cache too; an unshared inherited Cargo home is
replaced by that cache. If the login Cargo home is registered as a share,
macluster uses that path instead. Unset or unshared inherited `CCACHE_DIR` and
`SCCACHE_DIR` values receive reusable node-local caches separated by cluster
and toolchain. Shared and relative cache paths keep their usual behavior;
explicit absolute cache paths outside all configured shares fail before
execution. Init offers detected Cargo and Rustup homes, plus custom C/C++
compiler prefixes, as optional shares. Build systems
may still write project-defined artifacts to shared storage. Package installs
modify the selected shared environment, so do not run concurrent `pip install`
operations into the same environment.

`mkill` marks a pending task cancelled or sends a termination request to the
compute runner. Normal cancellation sends `SIGTERM`, then `SIGKILL` after 30
seconds if needed. `--force` requests immediate `SIGKILL`. An uncertain or
unreachable node remains reserved until the controller can reconcile it.

## First checks

```sh
macluster --version
macluster --config ~/.config/macluster/config.toml controller status
mtop --once
msub --help
```

Local unit tests and build checks do not verify a physical second Mac, SSH
credentials, the NFS export/mount, file permissions, power readings, or a
launchd restart. Those need to be checked on the actual cluster before using
it for long-running work.
