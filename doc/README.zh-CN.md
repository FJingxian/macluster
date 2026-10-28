# macluster

把多台 Mac 组成一个小型计算集群。用 Rust 编写，通过 SSH 管理节点，通过 NFS 共享文件。

[English](../README.md) · 简体中文

## 工作方式

- **登录 Mac**：接收任务、运行控制器，默认也存放共享文件。
- **计算 Mac**：执行任务。每台同时运行一个任务，不限制 CPU 核数或内存。
- 项目、软件环境和结果通过 NFS 共享。
- 登录 Mac 不接收计算任务，也可以指定另一台 Mac 专门存储文件。

目前适合家庭和实验室的小型集群，项目仍在早期阶段。

## 准备条件

- 每台机器运行 macOS 12 或更新版本。
- 编译应用需要 Rust 1.90 或更新版本。
- 在计算 Mac 上开启“远程登录”，确保登录 Mac 可以通过 SSH 连接。
- 共享目录的账户和文件权限允许各节点读写。
- 共享目录所在卷支持 macOS NFS 导出，例如 APFS；ExFAT 卷无法导出。

配置 NFS 和功耗采集工具时，可能需要各台 Mac 的管理员授权。应用二进制需要与目标 Mac 的 CPU 架构一致。

共享受保护目录或外接卷时，还可能需要在存储 Mac 的“系统设置 → 隐私与安全性 → 完整磁盘访问权限”中添加并开启 `/sbin/nfsd`。授权后在该 Mac 上执行 `sudo /sbin/nfsd restart`，再重试加入节点或共享目录。

## 安装

在登录 Mac 上，进入本仓库后执行：

~~~sh
cargo build --release --locked -p macluster-cli
packaging/scripts/install-user.sh
~~~

程序 `macluster` 和命令别名会安装到 `~/.local/bin`。将它加入 `PATH`：

~~~sh
export PATH="$HOME/.local/bin:$PATH"
~~~

把这一行加入 shell 配置文件，重新打开终端后也能使用。安装后的程序运行时不需要 Rust 或 Python。

分发时只需复制 `target/release/macluster`。匹配版本的功耗采集工具已经内嵌，无需单独下载 `macluster-power`。配置时会按需安装到系统受保护的位置，可能需要管理员授权。

## 创建集群

在登录 Mac 上初始化：

~~~sh
macluster init --name home --queue mini01 --shared-root /Users/Shared/macluster
~~~

加入一台计算 Mac。请将示例中的 SSH 用户和 IP 换成自己的：

~~~sh
mnode -a cluster-user@192.0.2.10
mnode -l
~~~

加入节点时会安装 Agent、写入配置并设置共享目录。如果还没有 SSH 密钥登录，程序会引导核对主机指纹并安装密钥。SSH 登录密码与各台 Mac 的管理员密码分别用于不同操作。

加入节点时还会在 NFS 客户端安装系统级 LaunchDaemon，开机后自动恢复已授权的挂载。失败后按 15、30、60 秒退避重试；检查共享来源和共享 ID，遇到路径被其他文件或挂载占用时保留数据并停止操作。旧版已登记的节点，再运行一次 `mnode -a 用户@地址` 即可修复挂载并安装恢复服务。移除节点和 `init` 会先停用恢复服务，再清理挂载。安装或修改服务时需要对应机器的管理员授权。

初始化完成后，macluster 会在当前图形登录会话中安装并启动用户级 LaunchAgent。关闭终端后，任务仍会继续调度；用户注销后服务会停止。

可以这样查看或管理服务：

~~~sh
macluster controller status
macluster controller stop
macluster controller start
~~~

`macluster controller run` 仍可用于前台排查。若前台 controller 已运行，`controller start` 会复用它；停止或重启前台实例时请先按 Ctrl-C。

## 提交任务

~~~sh
# 提交命令或脚本。
msub -q mini01 hostname
msub -q mini01 job.sh

# 执行交互命令，或打开交互 shell。
msub -Is python --version
msub -Is

# 查看任务和队列。
mjob
mqueue

# 查看输出或结束任务。将 1 换成提交后显示的任务编号。
mjob --log 1
mkill 1
~~~

命令含有重定向、管道等 shell 操作时，用引号包住，让计算节点执行完整命令：

~~~sh
msub --wrap 'python analysis.py > analysis.log 2>&1'
~~~

在共享目录中提交，任务就使用这个目录。在共享目录以外提交内联命令，任务会使用主共享根目录。也可以用 `--cwd PATH` 指定共享目录。

任务生成的相对路径文件保存在工作目录中。默认日志会在任务结束后同步到主共享目录。

## 共享项目和软件

增加一个项目共享目录：

~~~sh
mnode -a local:~/projects/example --share-id project \
  --mount-root /Users/Shared/macluster-shares/project
~~~

Python 环境、Homebrew 或编译器所在的目录也需要注册为共享目录。初始化时，`init` 会列出检测到的软件目录供你选择。

例如，将本机 Mamba 目录按原路径共享：

~~~sh
mnode -a "local:$HOME/mamba" --share-id mamba --mount-root "$HOME/mamba"
~~~

然后在登录终端激活环境，进入已共享的项目目录提交：

~~~sh
msub -Is python --version
msub -Is pip install . --break-system-packages
~~~

`msub` 会继承当前终端导出的环境变量，包括激活的 Python 环境。软件文件也必须共享，且激活环境在各节点上需要对应相同的绝对路径。任务若使用了未共享的激活环境，会在提交时被拒绝，不会悄悄改用计算节点上的软件。像 `ls` 这样解析到该环境之外的简单命令，不要求共享环境里的 Python 解释器。

shell 的别名和函数不会传给任务。环境变量会随任务保存，请避免把密钥等敏感信息传入任务。

## 查看资源

~~~sh
mtop
mtop --once
~~~

`mtop` 显示任务数、CPU、内存、磁盘 IO、网络，以及硬件支持的 GPU、温度、风扇和功耗数据。

通过 controller 启动只读浏览器面板：

~~~sh
macluster controller run --web
~~~

面板可查看节点详情、CPU 和内存历史、任务、队列及共享目录中的任务日志。服务只监听本机 `127.0.0.1`，并随控制器运行。如果控制器已经在运行，此命令会让它直接开启面板后返回。使用 `--no-open` 可打印一次性浏览器链接；使用 `--web-port PORT` 可指定端口。

用方向键或 `j`/`k` 选择节点，Enter 查看进程，`q` 退出。进程详情中，`c` 按 CPU 排序，`m` 按内存排序。

CPU 利用率可以超过 100%，例如有 8 个逻辑 CPU 的 Mac 最高为 800%。无法获取的硬件数据显示 `N/A`。

## 管理集群

| 命令 | 用途 |
| --- | --- |
| `mnode -l` | 查看节点和 NFS 共享路径。 |
| `mnode -rm NODE_ID` | 移除空闲且没有托管共享目录的节点。 |
| `mnode -rm NODE_ID --connect USER@IP[:PORT]` | 使用当前 SSH 地址移除地址已变化的节点，清理前核对登记的机器身份。 |
| `mnode -rm share:SHARE_ID` | 取消尚未完成的共享目录配置。 |
| `macluster init` | 确认重置当前集群，然后重新配置。 |
| `macluster init --force` | 重置时允许放弃已结束任务的待同步输出；活动任务仍需先结束。 |
| `macluster controller status` | 查看本机服务状态，不会启动服务。 |
| `macluster controller start/stop/restart` | 管理登录 Mac 上的后台控制器。 |

移除节点会直接验证机器 UUID、任务状态和待同步输出，无需先更新即将移除的 Agent。新连接地址会保存在移除记录中，便于中断后重试；NFS 授权仍按原登记地址清理。SSH 主机密钥校验保持启用，遇到密钥变化需先核实目标机器。

重置会保留共享目录里的数据文件，并归档旧配置和任务状态。

节点在同网段内更换 IP 后可以继续使用原节点 ID。macluster 会用登记的 MAC 地址和邻居表查找候选，再核对已信任的 SSH 主机密钥与机器 UUID；不会仅凭 MAC 地址接受陌生机器。

controller 每 30 秒检查已登记地址和局域网邻居。节点仍不可达时，完整网段扫描最多每 5 分钟一次，减少重复探测对本机控制面的影响；单次最多扫描 1,024 个地址，更大网段使用邻居表。核实地址变化后，先暂停派发新任务，等活动任务结束，再更新托管的 NFS 授权、挂载和各节点配置，保留原队列及任务历史。已结束任务的待同步输出会保留，迁移后继续同步。涉及管理员权限时会提示对应机器；后台 controller 无法取得授权时，可在前台运行 macluster 命令继续。迁移记录支持中断后重试。

控制器常驻在登录 Mac，负责接收任务、调度和共享监控。移除节点时只排空该节点，其他计算节点可以继续运行。加入节点、变更 NFS 共享和更新 Agent 会进行集群级排空，再应用配置。旧版控制器不支持在线维护时，程序会先询问是否关闭，并说明如何重启。重置和更新 controller 程序仍会协调停止与重启。常规操作检测到已知 Agent 版本或 hash 不一致时，会先自动更新；移除节点直接执行上述安全检查。

如果要用另一台 Mac 存储文件，在初始化时指定 `--primary-nfs`：

~~~sh
macluster init --name home --queue mini01 \
  --primary-nfs 'storage-user@198.51.100.10:22:/Volumes/Data/macluster' \
  --shared-root /Users/Shared/macluster
mnode -a local
~~~

请替换示例中的存储账户、IP 和目录。存储 Mac 同样不加入计算队列。

## 遇到问题

执行 `macluster --help` 或 `msub --help` 查看参数。

任务一直等待时，检查控制器是否运行、队列中是否有 `READY` 的计算节点。找不到工具时，检查软件目录是否共享，以及提交终端是否激活了正确环境。

如果服务没有启动，使用 `macluster controller status` 查看状态，再用 `macluster controller start` 重试。服务日志位于 `~/Library/Logs/macluster/`。

## 许可证

采用 [GNU GPL v3 或更新版本](../LICENSE)（`GPL-3.0-or-later`）。允许商业使用；分发软件时需要遵守 GPL 的许可和源码提供要求。
