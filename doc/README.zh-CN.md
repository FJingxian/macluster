# macluster

将多台 Mac 组成个人计算集群：在一台 Mac 上提交命令，让其他 Mac 执行，通过终端或浏览器查看资源和任务。

[English](../README.md) · 简体中文 · [Agent skill](../skills/macluster/SKILL.md)

使用 Rust 编写，只需分发一个二进制。SSH 连接节点，NFS 共享项目、软件和结果。

![mtop 实时资源监控与进程 CPU、内存排序](assets/mtop.gif)

*选择节点、展开进程，再切换 CPU 或内存排序。演示来自真实集群录制，机器标识和进程名已匿名处理。*

## 工作方式

```text
登录 Mac                         计算 Mac
命令行 + 后台 controller  ───►   每台同时执行一个任务
默认提供 NFS 存储         ◄──►   共享项目和软件
```

登录 Mac 不加入计算队列。每个任务独占一台计算节点，不限制 CPU 核数或内存。初始化时也可以指定另一台 Mac 提供存储。

项目仍处于早期阶段，面向个人和实验室集群，以 macOS 账户及共享目录作为信任边界。

## 安装

要求：macOS 12 或更新版本；计算节点开启“远程登录”，登录 Mac 可以通过 SSH 连接。源码编译需要 Rust 1.90 或更新版本。

在准备作为登录节点的 Mac 上进入仓库执行：

```sh
cargo build --release --locked -p macluster-cli
packaging/scripts/install-user.sh
export PATH="$HOME/.local/bin:$PATH"
```

将 PATH 这一行加入 shell 配置，方便后续使用。分发时只需复制 `target/release/macluster`，功耗/风扇 helper 已内嵌。运行 macluster 不需要安装 Rust 或 Python；二进制需要支持目标机器的 CPU 架构。

只复制二进制时可以运行 `macluster 子命令`；`mtop` 这类短命令是安装脚本创建的软链接。使用下载的二进制时，运行 `packaging/scripts/install-user.sh /path/to/macluster "$HOME/.local/bin"`，然后将该目录加入 PATH。

下文使用完整命令；安装脚本也提供 `msub`、`mjob`、`mqueue`、`mkill`、`mtop`、`mnode`、`mfans` 别名。controller 服务命令仍可用于手动维护，但不再显示在主帮助中。

## 创建集群

```sh
# 在登录 Mac 上执行，按交互提示完成配置。
macluster --init --name home --queue default --shared-root /Users/Shared/macluster

# 将示例中的 SSH 账户和地址换成计算节点的信息。
macluster node -a worker@192.0.2.10
macluster node -l
```

节点通过 Agent 和共享存储验证后才会进入正式集群。加入失败的尝试保留在恢复记录中，可用 `macluster node --failed` 查看错误，再重试原来的加入命令。

加入节点时会安装 Agent、配置共享空间。若没有 SSH 密钥登录，可在核对指纹并输入远程账户登录密码后安装密钥。NFS 和特权 helper 的配置还可能需要每台相关 Mac 的管理员授权，两者用途不同。

初始化会安装用户级后台 LaunchAgent。关闭终端不影响 controller，注销该 macOS 用户会使服务停止。任务调度需要 controller；查看任务、队列可在它停止时读取已保存的状态。

```sh
macluster controller status
macluster controller start
macluster controller stop
```

`controller run` 用于前台排查。仅需启动服务时不要重新执行 `init`：已有配置时，它会询问是否重置集群。

## 提交任务

![提交任务、查询状态与队列，再读取运行结果](assets/jobs.gif)

*一段完整流程：提交 → 运行 → 完成 → 查看输出。*

```sh
macluster submit hostname                       # 批处理命令
macluster submit job.sh                         # 脚本
macluster submit -q default --node default-001 hostname
macluster submit -Is python --version           # 交互命令，需要真实终端
macluster submit -Is                            # 交互 shell

macluster job                                  # 活动任务
macluster job --all                             # 包括已结束任务
macluster job 1                                # 详情，1 换成实际任务 ID
macluster job --log 1                          # 查看输出
macluster queue
macluster kill 1
```

程序参数放在命令之后。含有重定向、管道等 shell 操作时，加引号让计算节点执行完整命令：

```sh
macluster submit --wrap 'python analysis.py > analysis.log 2>&1'
macluster submit -v python analysis.py          # 开启详细资源日志
```

带时间戳和 CPU/内存的详细日志**默认关闭**，需要时用 `submit -v` 开启。

**文件放在哪里：**在已注册共享目录内提交，就以该目录为工作目录；在共享目录之外提交内联命令，则使用主共享根目录。`--cwd PATH` 可以显式指定共享目录。相对路径结果写在任务工作目录，默认捕获日志在任务结束后同步到主共享目录。计算节点不能直接读取登录 Mac 上任意未共享的文件。

## 实时查看单个任务

![订阅运行中任务的 CPU 和内存占用](assets/profile.gif)

*录制使用短时示例任务。无需开启详细日志；关闭订阅后，任务继续运行。*

```sh
macluster job --metrics 1
macluster job --metrics 1 --follow --json
```

通过运行中的 controller 订阅任务进程组的 CPU/RSS，提交时没有加 `-v` 也可以使用。同一任务的多个查看者共用一份约每 5 秒更新的样本；关闭订阅会停止按需采集，不会取消任务。第一次观测还不能计算区间 CPU，值为 null，通常下一次观测后可用。`--follow --json` 每行输出一条 JSON，并在任务结束后退出。

这是实时采样数据，不能补齐订阅前的完整资源历史。RSS 是进程驻留内存之和，可能重复计算共享页；峰值是采样峰值。采集仍有开销，但查看者增加不会重复采集同一个任务。接口和限制见[任务资源订阅说明](job-resources.md)。`job --log --follow` 仍然等待任务结束、日志发布后才读取，并不是实时输出流。

## 共享项目和环境

```sh
# 在所有节点使用相同的项目路径。
macluster node -a "local:$HOME/projects/example" --share-id project \
  --mount-root "$HOME/projects/example"

# 共享包含软件环境的安装目录。
macluster node -a "local:$HOME/mamba" --share-id mamba \
  --mount-root "$HOME/mamba"
```

在登录终端激活环境，进入共享项目目录，再提交：

```sh
macluster submit -Is python --version
macluster submit -Is pip install -e .
```

`submit` 会继承导出的环境变量，并映射已注册共享路径。**环境变量不会自动共享软件文件**；激活环境在各节点上必须解析到相同的绝对路径。未共享工具链不会被悄悄替换成计算节点自带的软件，标准 macOS 命令仍可使用。shell 别名、函数，以及节点专用的 HOME、用户名、临时目录、SSH agent 值不会直接继承。

环境变量会随任务保存，请避免导出密钥等敏感信息。不要同时向同一个共享环境安装软件。软件共享挂载可能遮住目标目录里原有的安装，变更前先检查映射。

共享卷需要支持 NFS 导出，例如 APFS；ExFAT 无法导出。受保护目录和外接卷可能需要在**存储 Mac** 上为 `/sbin/nfsd` 开启“完整磁盘访问权限”，授权后在该机重启 nfsd，再重试加入节点。

## 查看资源

```sh
macluster top                                  # 终端面板
macluster top --once                           # 单次表格
macluster --web 127.0.0.1:8080                 # 本机浏览器面板
```

终端中，方向键或 `j`/`k` 选择节点，Enter 打开/收起进程详情，`c` 按 CPU 排序，`m` 按内存排序，`q` 退出。进程先显示快速预览，再更新为区间采样结果；预览会注明 CPU 是平均值、内存是 RSS。

CPU 占用为所有逻辑 CPU 之和，例如 8 个逻辑 CPU 最高为 800%。GPU、温度、风扇、功耗取决于硬件与 helper 支持情况，无法获取时显示 `N/A`。

浏览器面板只读，监听 `127.0.0.1`；当前 `--web` 只接受回环地址。加 `--no-open` 可打印访问链接；兼容的 controller 已运行时可以直接开启面板，无需重启。`mqueue` 也可通过 `macluster queue` 使用。

## 管理和维护

| 命令 | 用途 |
| --- | --- |
| `macluster node -l` | 查看正式节点（READY / OFFLINE）和通用 NFS 映射 |
| `macluster node --failed` | 查看未完成的节点或共享操作及错误原因 |
| `macluster node -rm NODE_ID` | 移除空闲计算节点；托管共享的节点需先迁移存储 |
| `macluster node -rm NODE_ID --connect USER@IP[:PORT]` | 使用新地址连接并核实原机器身份后移除 |
| `macluster node -rm share:SHARE_ID` | 取消未完成的共享配置 |
| `macluster fans --status [--node ID]` | 查看风扇策略与支持情况 |
| `macluster fans --auto [--node ID]` | 按 40–80°C 线性调速 |
| `macluster fans --power [--node ID]` | 按 40–80°C 对数曲线调速 |
| `macluster fans --reset [--node ID]` | 恢复系统风扇控制 |
| `macluster init` | 确认重置，归档旧状态，然后重新配置 |
| `macluster init --force` | 允许放弃已结束任务的待同步输出；活动任务仍阻止重置 |

重置清理托管的 NFS 挂载/导出，并保留共享数据文件；请阅读确认提示。风扇控制使用 AppleSMC 私有接口，支持情况取决于机型，不支持的机器维持系统控制。

本机初始化时会安装功耗采样服务，交互式 `mtop` 也可以单独请求授权来安装或修复；拒绝授权后仍可查看其他资源。功耗读取短暂失败时保留上一笔有效读数，并显示年龄和错误，最长沿用原有的 60 秒有效期。M 系列 MacBook Air 没有风扇，因此风扇转速显示 N/A。

已知 Agent 版本不一致时自动进入更新流程。特权服务具有独立版本，普通 Agent 更新复用当前服务；首次安装、服务升级或修复仍可能需要每台相关机器的管理员授权。程序不保存密码。

需要独立存储 Mac 时：

```sh
macluster init --name home --queue default \
  --primary-nfs 'storage@198.51.100.10:22:/Volumes/Data/macluster' \
  --shared-root /Users/Shared/macluster
```

存储 Mac 不加入计算队列。同网段 IP 变化时，核实 SSH 信任与机器身份后可以保留节点 ID；迁移等待活动任务结束，NFS 调整可能需要管理员授权。

## 排查问题

| 现象 | 先检查 |
| --- | --- |
| 任务一直等待 | `controller status`、`job JOBID`、`node -l`；队列需要就绪的计算节点 |
| 找不到 Python/编译器 | 登录终端激活了正确环境，软件安装目录已共享 |
| 工作目录不对 | `node -l` 的映射；在共享目录中提交或用 `--cwd` |
| NFS 拒绝导出 | 存储 Mac 的文件系统、目录权限及 nfsd 隐私授权 |
| controller 无法启动 | `controller status`，服务日志位于 `~/Library/Logs/macluster/` |

用 `macluster --help`、`macluster submit --help` 查看选项。保留 SSH 主机密钥校验；指纹变化时先核实机器身份，再更新信任记录。

## Agent skill

仓库包含 [macluster skill](../skills/macluster/SKILL.md)，帮助代理检查集群、提交任务、正确使用环境与共享路径并排查失败。

在本仓库执行以下命令，可安装到 Codex：

```sh
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/macluster "${CODEX_HOME:-$HOME/.codex}/skills/"
```

使用示例：“用 `$macluster` 将当前共享目录中的分析任务提交到集群，并检查结果。”

## 许可证

[GNU GPL v3 或更新版本](../LICENSE)（`GPL-3.0-or-later`）。允许商业使用；分发时需要遵守 GPL 的许可及源码提供要求。
