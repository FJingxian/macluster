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
cargo build --release --locked --workspace
packaging/scripts/install-user.sh
~~~

程序、功耗采集工具和命令别名会安装到 `~/.local/bin`。将它加入 `PATH`：

~~~sh
export PATH="$HOME/.local/bin:$PATH"
~~~

把这一行加入 shell 配置文件，重新打开终端后也能使用。安装后的程序运行时不需要 Rust 或 Python。

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

启动控制器，并保持它运行：

~~~sh
macluster controller run
~~~

再打开一个终端提交任务。

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

`msub` 会继承当前终端导出的环境变量，包括激活的 Python 环境。软件文件也必须共享，且激活环境在各节点上需要对应相同的绝对路径。未共享的激活环境会在提交时被拒绝。

shell 的别名和函数不会传给任务。环境变量会随任务保存，请避免把密钥等敏感信息传入任务。

## 查看资源

~~~sh
mtop
mtop --once
~~~

`mtop` 显示任务数、CPU、内存、磁盘 IO、网络，以及硬件支持的 GPU、温度、风扇和功耗数据。

用方向键或 `j`/`k` 选择节点，Enter 查看进程，`q` 退出。进程详情中，`c` 按 CPU 排序，`m` 按内存排序。

CPU 利用率可以超过 100%，例如有 8 个逻辑 CPU 的 Mac 最高为 800%。无法获取的硬件数据显示 `N/A`。

## 管理集群

| 命令 | 用途 |
| --- | --- |
| `mnode -l` | 查看节点和 NFS 共享路径。 |
| `mnode -rm NODE_ID` | 移除空闲且没有托管共享目录的节点。 |
| `macluster init` | 确认重置当前集群，然后重新配置。 |
| `macluster init --force` | 重置时允许放弃已结束任务的待同步输出；活动任务仍需先结束。 |

重置会保留共享目录里的数据文件，并归档旧配置和任务状态。

修改节点或共享目录时，程序可能询问是否关闭控制器。操作完成后按提示重新启动。检测到已知 Agent 版本或 hash 不一致时，会在执行操作前自动更新。

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

仓库提供 [launchd 服务模板](../packaging/launchd/org.macluster.controller.plist)，修改其中的路径后再安装。

## 许可证

采用 [GNU GPL v3 或更新版本](../LICENSE)（`GPL-3.0-or-later`）。允许商业使用；分发软件时需要遵守 GPL 的许可和源码提供要求。
