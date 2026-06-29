# sandboxfs 设计与实现计划

## Context

用户希望构建一个基于 [`cberner/fuser`](https://github.com/cberner/fuser) 的内存态 sandbox 文件系统：

- 只通过 `sandboxfs run <name>` 显式启动一个前台 sandbox session；不使用隐藏 `sandboxfsd`，也不自动启动后台 daemon。
- 不提供全局 `sandboxfs list`。正在运行的 sandbox session 是用户自己前台启动和管理的。
- 所有 sandbox 状态只存在于 `sandboxfs run <name>` 进程内存中；前台进程退出或收到 `sandboxfs <name> destroy` 后，状态、pending request 和日志清理后消失。
- 短生命周期控制命令使用 `sandboxfs <name> ...` 形式连接对应 session 的 Unix domain socket，例如 `sandboxfs <name> mount/umount/chmod/chown/chattr/hide/allow/deny/...`。
- `sandboxfs run <name>` 只创建/注册一个 sandbox 状态，不立刻挂载 FUSE；需要 `sandboxfs <name> attach <mountpoint>` 才暴露到本地目录。永久 attach 支持同一个 sandbox 同时挂到多个不同 mountpoint；解除时使用 `sandboxfs <name> detach <mountpoint>` 精确卸载对应 mountpoint。重复 attach、重复 detach、路径不属于该 sandbox、路径不正确或未挂载都必须失败并返回非零退出码。
- 支持把本地已存在的文件/目录映射到 sandbox 内路径，后挂载覆盖先挂载。
- sandbox 内自动创建的虚拟目录应表现为不可写（类似 `chattr +i` 的效果），且销毁后不保留任何数据。
- 支持临时覆盖 metadata（例如 chmod/chown/chattr），不修改底层真实文件；如果底层文件本来不可读，sandbox 内把 mode 显示成 `777` 也不会绕过真实读权限。
- `sandboxfs <name> chmod/chown/chattr/...` 的语义是：sandboxfs CLI 为这次命令在运行期目录下创建一个临时 FUSE mountpoint，真实调用 PATH 上解析到的对应命令（例如 `chmod`、`chown`、`chattr`，不写死 `/bin/...`）作用在这个临时挂载点上，命令结束后立即 detach/unmount 并清理临时目录；这些由 sandboxfs CLI 发起的 FUSE metadata 请求被视为可信，直接无条件 allow，不需要用户二次授权。auto-allow 不代表强制成功：如果本机命令失败、路径不存在、或 FUSE 暂不支持对应 metadata 操作，就按普通命令失败方式返回错误。
- 对用户绕过 sandboxfs CLI、直接在 FUSE 挂载点上执行 chmod/chown 等 metadata 修改操作，FUSE 通常只能看到 `setattr` 请求（path + metadata 变化），看不到用户原始 shell 命令；sandboxfs 需要生成 operation id、记录一条待授权请求并挂起，等待 TUI 或 CLI allow/deny。
- 提供 monitor/mount/metadata 等查看命令；monitor 按 tail/tail -f 语义读取运行期日志。
- 文件内容与目录结构的持久修改不会写回底层真实文件；第一版对 create/write/truncate/unlink/rename 等内容/结构修改直接返回只读或不支持错误，只实现读路径和 metadata override。
- runtime 目录选择优先 `SANDBOXFS_RUNTIME_DIR`，否则用户态用 `$XDG_RUNTIME_DIR/sandboxfs`，系统态用 `/run/sandboxfs`；目录权限默认 `0700`。socket 默认位于 `<runtime>/<name>.sock`，`SANDBOXFS_SOCKET` 可覆盖。日志默认位于 `<runtime>/<name>.log`，`SANDBOXFS_LOG_DIR` 可覆盖目录。

## Approach

采用“前台 session + 短生命周期控制命令 + TUI”的架构：

- `sandboxfs run <name>` 前台 session 负责：
  - 持有该 sandbox 的全部内存状态。
  - 创建 per-sandbox Unix domain socket，供其他 `sandboxfs <name> ...` 控制命令和 TUI 连接。
  - 启动时清空对应日志，但不执行 FUSE mount。
  - 在 `sandboxfs <name> attach <mountpoint>` 时启动/管理对应 fuser 文件系统实例；同一个 sandbox 可有多个永久 attach mountpoint。
  - 在 `sandboxfs <name> detach <mountpoint>` 时只卸载指定 mountpoint。
  - 记录该 sandbox 的操作日志到运行期日志文件，并保留 pending request 状态在内存中。
  - 处理 FUSE metadata 修改请求：若请求来自 sandboxfs CLI 标记的可信子进程，则跳过授权等待并按当前 FUSE 能力正常处理；支持的操作更新 override 并返回成功，不支持或非法的操作返回普通错误；否则挂起等待 TUI 或 CLI 决策。
- `sandboxfs` CLI 负责：
  - `sandboxfs run <name>`：启动前台 session。
  - `sandboxfs <name> destroy`：请求 session 清理状态、pending request、日志、mountpoint 并退出。
  - `sandboxfs <name> attach <mountpoint>` / `detach <mountpoint>`。
  - `sandboxfs <name> mount <local> <on_fs>` / `umount <on_fs>` / `hide <on_fs>`；无参数 `sandboxfs <name> mount` 列出映射与 hide 信息。
  - `sandboxfs <name> chmod/chown/chattr ...`：CLI 先通过 IPC 请求 session 为本次操作创建临时 attach mountpoint（位于 runtime 目录，例如 `$XDG_RUNTIME_DIR/sandboxfs/tmp/<name>-<operation_id>/`），再在该目录作为 current working directory 的情况下 fork/exec PATH 上解析到的命令名。session 根据 FUSE request 的 pid/uid/path/operation token 将其自动 allow；子进程 exit status 原样作为 CLI 结果返回，随后 session detach 并清理临时 mountpoint。
  - `sandboxfs <name> allow <operation_id>` / `deny <operation_id>` 可以在没有 TUI 时处理 pending request，便于自动化。
  - `sandboxfs <name> allow --do-nothing <operation_id>` 只让挂起的 FUSE 请求返回成功，不改 sandbox metadata、不改底层文件。
- `sandboxfs-access-tui <name>` 负责：
  - 连接对应 foreground session 的 socket。
  - 展示 pending metadata 请求。
  - 第一行显示 sandboxfs 能重建出的“实际操作描述”（例如 `chmod mode=<...> path=<...>` 或 `chown uid=<...> gid=<...> path=<...>`，不是 shell 原始命令）。
  - 提供 allow / deny / edit-command 三种操作；edit-command 后续通过 sandboxfs 的可信 CLI 路径运行用户修改后的命令，结果只影响 sandbox metadata override，绝不真实修改底层文件。
- 文件系统层采用 overlay/union 思路：
  - 每次 `sandboxfs <name> mount <local_path> <on_fs_path>` 记录一个映射层。
  - 路径解析时从后往前匹配 layer，后添加的 layer 覆盖先添加的 layer。
  - `hide <on_fs_path>` 记录隐藏规则；若之后又有新的 mount 覆盖同一路径，则按“更新的 layer 可见”处理。
  - 自动生成的中间虚拟目录仅保存在内存树中，默认不可写；内容/结构写操作不写回真实文件，第一版直接返回 EROFS/EPERM/ENOTSUP。
- metadata override：
  - `sandboxfs <name> chmod/chown/chattr ... <on_fs_path>` 真实运行本机命令在临时 FUSE mountpoint 上；session 将该 CLI 子进程产生的 FUSE `setattr`/metadata request 视为可信请求，不进入 pending/allow 流程；如果该操作被 sandboxfs 支持，则更新内存 override 表并返回成功，否则正常返回 FUSE/系统错误。临时 mountpoint 仅用于这次命令，结束后销毁。
  - 用户手动在 FUSE mountpoint 运行 chmod/chown/chattr 时，session 只看到 FUSE `setattr`，生成 pending request，分配 operation id，写日志为 `<operation_id> <operation-description>`，然后阻塞等待 TUI/CLI 决策。
  - allow 的几种语义分开实现：
    - allow/apply：按 pending request 或用户编辑后的可信命令尝试更新 sandbox override；成功则让 FUSE 请求成功返回，失败则返回对应错误。
    - allow --do-nothing：不更新 override，只让 FUSE 请求成功返回。
    - deny：让 FUSE 请求失败返回，并清理 pending 状态。

## Files

- `Cargo.toml`
- `src/bin/sandboxfs.rs` — 主 CLI / foreground session entrypoint
- `src/bin/sandboxfs-access-tui.rs` — 授权 TUI
- `src/lib.rs`
- `src/session.rs` — foreground session server and state machine
- `src/fs.rs` — fuser 文件系统实现
- `src/state.rs` — sandbox、layer、hide、metadata override 状态
- `src/ipc.rs` — CLI/TUI 与 foreground session 通信协议
- `src/log.rs` — sandbox 操作日志
- `src/path.rs` — sandbox 路径规范化与真实路径映射
- `src/runtime.rs` — runtime/socket/log/temp mount 路径选择
- `src/tui.rs` — ratatui UI
- `tests/` — 测试套件：单元测试、CLI/TUI/IPC 集成测试、FUSE 行为测试、BDD 场景测试

## Steps

- [x] 明确 CLI 语法、前台 session 生命周期、`attach/detach` 行为，以及 runtime/log/socket 路径环境变量。
- [x] 创建 Rust project，并加入基础依赖。
- [x] 定义核心数据模型：sandbox、多个 permanent attach mountpoint、temporary operation mountpoint、mount layer、hide rule、virtual dir、metadata override、pending metadata request、trusted operation token/pid、operation id、runtime dir、log file path。
- [x] 实现路径规范化和 overlay 解析规则。
- [x] 实现 fuser 文件系统的只读文件/目录浏览、lookup、getattr、readdir、open、read 等基础能力；create/write/truncate/unlink/rename 等内容/结构修改第一版返回只读或不支持错误。
- [x] 实现 runtime 目录选择：优先 `SANDBOXFS_RUNTIME_DIR`，否则用户态用 `$XDG_RUNTIME_DIR/sandboxfs`，系统态用 `/run/sandboxfs`；目录权限默认 `0700`。
- [x] 实现 `sandboxfs run <name>` / `sandboxfs <name> destroy`；`run` 清空对应运行期日志但不挂载 FUSE，`destroy` 清理内存状态、pending 请求和日志文件并退出。不实现全局 `list`。
- [x] 实现 `sandboxfs <name> attach <mountpoint>` / `detach <mountpoint>`；`attach` 才调用 fuser mount，支持多个不同 mountpoint；同一路径重复 attach、mountpoint 不存在/不是目录/已被其他 sandbox 使用时失败；`detach <mountpoint>` 只卸载对应 mountpoint，重复 detach、路径不匹配、路径未挂载或属于其他 sandbox 时失败。
- [x] 实现 `sandboxfs <name> mount <local> <on_fs>` / `umount <on_fs>` / `hide <on_fs>`，并写入日志；无参数 `sandboxfs <name> mount` 用于列出映射与 hide 信息。
- [x] 实现 `sandboxfs <name> chmod/chown/chattr ...`：为该命令创建 runtime 下的临时 FUSE mountpoint、注册 trusted operation token/pid、规范化可识别的 sandbox 路径参数、以临时 mountpoint 为 current working directory fork/exec PATH 上解析到的命令、由 FUSE setattr/metadata request 在支持时更新内存 metadata/flag override，不修改真实文件；命令失败或操作不支持时正常报错，最后 detach 并清理临时 mountpoint。
- [x] 实现 FUSE metadata 修改请求拦截：可信 CLI 请求跳过授权等待并正常执行/报错；非可信请求生成 operation id、写 `<id> <operation-description>` 日志、挂起请求、等待 allow/deny。
- [x] 实现 `sandboxfs <name> allow` 无参数列出 pending 请求，`allow <id>`、`allow --do-nothing <id>`、`deny <id>` 处理指定请求。
- [~] 实现 `sandboxfs-access-tui` 的 pending request 展示与 allow/deny/edit。当前实现支持展示、allow、deny、do-nothing；edit-command 仍需补完整可信命令重跑流。
- [x] 实现 `monitor` / `monitor -f`，按 tail/tail -f 语义读取运行期日志文件。
- [x] 实现 `sandboxfs <name> metadata` 列出该 sandbox 内外 metadata 不一致的路径；不保留全局 `sandboxfs metadata`。
- [~] 按 TDD/BDD 组织测试：已有核心单元测试和 CLI foreground session 集成测试；仍需补 TUI 测试、IPC 错误恢复测试、更多 FUSE success/error 测试和 BDD 场景测试。所有集成/行为/FUSE 测试必须直接创建独立 temp dir，并为每个测试设置唯一 `SANDBOXFS_RUNTIME_DIR`、`SANDBOXFS_SOCKET`、sandbox name、日志路径和 mountpoint，避免共享 session/socket/log；测试结束清理 temp dir/session/mount，确保用例之间隔离且可并行运行。需要真实 FUSE 的测试默认 gated/ignored，通过环境变量显式开启。
- [x] 补充 README 使用示例和已知限制。

## Verification

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo test --lib` 覆盖核心单元测试。
- `cargo test --test cli_session` 覆盖 CLI foreground session 用户接口集成测试，包括成功命令、错误参数、错误退出码和日志行为；每个测试使用独立 temp dir/runtime/socket/sandbox。
- 待补：`cargo test --test tui` 覆盖 TUI 用户接口集成测试，包括 pending request 展示、allow、deny、edit-command 和错误反馈；每个测试使用独立 temp dir/runtime/socket/sandbox。
- 待补：`cargo test --test ipc` 覆盖 session/socket IPC 集成测试；每个测试启动自己的 foreground session 和 socket，避免测试间共享状态。
- 待补：`cargo test --test behavior` 覆盖 BDD 用户行为场景；每个 scenario 使用独立 temp dir/runtime/socket/sandbox/mountpoint，可并行运行。
- 待补：`cargo test --test fs_errors` 覆盖不依赖真实 mount 的 FUSE/filesystem 错误语义单元或模拟测试。
- 待补：`SANDBOXFS_RUN_FUSE_TESTS=1 cargo test --test fuse_behavior -- --ignored` 在支持 FUSE 的 Linux 环境中运行真实挂载测试，覆盖 FUSE filesystem 成功路径与错误路径；每个测试使用独立 temp mountpoint 并在 drop/teardown 中强制 detach/unmount。
- 在支持 FUSE 的 Linux 环境中手动验证：
  - `sandboxfs run demo` 前台启动后确认不会立刻创建 FUSE mount。
  - `sandboxfs demo attach /some/mountpoint` 后确认 FUSE 可访问，`sandboxfs demo detach /some/mountpoint` 后解除。
  - 对同一 sandbox attach 到多个不同 mountpoint，确认每个 mountpoint 都可访问同一 sandbox 状态；detach 其中一个不影响其他 attach。
  - 验证 attach/detach 错误语义：重复 attach 同一路径失败，detach 次数太多失败，detach 错误路径/未挂载路径/其他 sandbox 路径失败，mountpoint 不存在或不是目录时 attach 失败。
  - 显式把 `demo` 暴露到某个本地 mountpoint 后，再添加多个重叠 mount，确认后者覆盖前者。
  - mount 到未创建的 sandbox 路径，确认中间虚拟目录可见但不可写。
  - 尝试 create/write/truncate/unlink/rename，确认不会修改底层真实文件，第一版返回只读或不支持错误。
  - `sandboxfs demo chmod/chown/chattr` 后确认会创建临时 FUSE mountpoint、实际 PATH 上的本机命令在该 mountpoint 下执行、不会要求 allow；支持的操作会改变 sandbox 内 metadata/flag 且真实文件 metadata 不变；不支持的操作或命令失败时正常返回错误；命令结束后临时 mountpoint 被清理。
  - 直接绕过 sandboxfs CLI、在 sandbox 挂载点执行 `chmod`/`chown`，确认请求挂起、日志包含 operation id，并可通过 TUI 或 `sandboxfs demo allow/deny` 处理。
  - `sandboxfs demo allow --do-nothing <id>` 后确认原始操作返回成功但 metadata override 不变化。
  - `hide` 后确认路径消失，之后新 mount 到同一路径可重新显示。
  - `monitor -f` 能持续看到 add/del/hide/chmod/chown 请求日志。
  - `metadata` 能列出所有 metadata override。

## Confirmed decisions

- `sandboxfs run <name>` 是唯一创建 sandbox session 的方式；不使用单独 `sandboxfsd`，不自动启动后台 daemon，不保留 `sandboxfs list`。
- `sandboxfs <name> attach <mountpoint>` / `sandboxfs <name> detach <mountpoint>` 用于把 sandbox 暴露/解除到本地目录；同一个 sandbox 支持多个永久 attach，detach 必须指定正确 mountpoint，重复 detach 或路径错误必须失败。
- IPC 使用 Unix domain socket；默认放在 runtime 目录，`SANDBOXFS_SOCKET` 可覆盖。
- runtime 目录优先 `SANDBOXFS_RUNTIME_DIR`，否则用户态使用 `$XDG_RUNTIME_DIR/sandboxfs`，系统态使用 `/run/sandboxfs`。
- `sandboxfs <name> destroy` 清理该 sandbox 的内存状态、pending 权限请求和 monitor 日志，并让前台 session 退出。
- `sandboxfs <name> chmod/chown/chattr` 不依赖用户手动 attach；它会为本次命令创建临时 FUSE mountpoint，运行 PATH 上的对应命令，结束后立即 detach/清理。
- `sandboxfs <name> allow` 无参数列出所有等待授权的 pending 请求；`allow/deny <operation_id>` 处理单个请求。
- `sandboxfs <name> chmod/chown/chattr` 的唯一区别是跳过授权等待；如果命令失败、路径不存在或 FUSE 不支持，仍然正常返回错误。
- 对 `sandboxfs <name> chmod/chown/chattr` 参数里的 sandbox 绝对路径，CLI 会做保守规范化：把 `/a/b` 改成临时 mountpoint cwd 下的 `./a/b`；相对路径保持不变；无法安全识别路径参数的复杂选项第一版直接报错，避免误操作宿主机路径。
