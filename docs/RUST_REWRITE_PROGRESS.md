# SETools Rust 重写进度

最后更新：2026-08-27（Asia/Shanghai）

当前阶段：首个 x86_64 Linux portable 版本已可发布；纯 Rust binary-policy parser
已开始 metadata 垂直切片

CLI 兼容目标：SETools 4.7.1

## 项目边界

- 本仓库独立构建、测试和发布。
- 实现不依赖 legacy SETools Python/Cython 源码或运行环境。
- 默认 source build 的 native 依赖仅为 libsepol 及编译 C bridge 所需的 C toolchain；
  不依赖 libselinux/PCRE2。
- x86_64 Linux portable archive 使用固定 libsepol 3.11 构建 static PIE，目标系统无需
  安装 libsepol、libselinux、PCRE2、libgcc 或特定 glibc shared object。
- `checkpolicy` 只用于编译 Rust integration-test 的 synthetic policy fixtures。
- Cargo 使用标准 `target/` 输出目录。

## 已完成

### M0：兼容与性能基线

- [x] `benchmarks/cli-v1.toml` 冻结 8 个端到端 CLI 场景；Linux-only、stdlib-only
  `scripts/benchmark-cli.py` 使用 `wait4(2)` 记录每个子进程的 wall time 和 peak RSS，
  同时保存 raw samples、min/median/max、policy/binary SHA-256 与环境信息。
- [x] 1.9 MiB 真实 `policy` 的 7 个默认场景 Rust 基线已保存在
  `docs/benchmarks/2026-08-27-cli-v1-rust.json`；外层 oracle 仓库另存 4.7.1 Python
  原始样本与逐场景比值，不成为产品依赖。
- [~] 手动 `sediff-full` 场景已冻结，但同一真实 policy 的当前运行在 prolonged
  analysis 后收到 SIGKILL；当前环境无法证明具体资源限制，因此不声明成功的
  wall-time/peak-RSS baseline。

### M1：workspace、bridge 与 owned model

- [x] 七 crate workspace 与六个 binary entry point。
- [x] project-owned C bridge、opaque native handle 和 Rust RAII 封装。
- [x] policy metadata、type/attribute/alias、class/permission、Boolean/conditional、
  TE/xperm、filename transition、role/RBAC 和 MLS range transition snapshot。
- [x] native policy 在 loader 返回 owned `Policy` 前释放。
- [x] raw libsepol 类型与常规 `unsafe` 不离开 `setools-sepol`。
- [x] running-policy discovery 由安全 Rust 读取 `/proc`、SELinuxfs 与
  `/etc/selinux/config`，保持 current policy 和版本化 fallback 顺序；bridge ABI 6
  只提供 libsepol policy-version 范围。

### M2：`sesearch`

- [x] 标准与扩展 TE rule、filename transition、conditional 查询和渲染。
- [x] RBAC 与 MLS range-transition 查询和渲染。
- [x] exact/regex、direct/indirect、class/permission、Boolean 和 range criteria。
- [x] help/version、verbose/debug、参数错误、load/query error、broken pipe。
- [x] 所有输出显式确定性排序。
- [x] release binary 构建成功。

### M3：`seinfo`

- [x] 补齐 common/class permissions、role authorized types、user/MLS、constraint、
  default、policy capability 和 security-context owned model。
- [x] 在 C bridge 内复制全部 SELinux/Xen labeling data，并在 loader 返回前释放
  native policy；owned model 不保存 libsepol pointer。
- [x] 实现 statistics 以及 Boolean、category、class、common、constraint、default、
  permissive、polcap、role/role-types、sensitivity、typebounds、type、attribute、user、
  validatetrans component。
- [x] 实现 SELinux `fs_use`、`genfscon`、`ibpkeycon`、`ibendportcon`、`initialsid`、
  `netifcon`、`nodecon`、`portcon` 查询。
- [x] 实现 Xen `devicetreecon`、`iomemcon`、`ioportcon`、`pcidevicecon`、`pirqcon`
  查询及跨 target 参数校验。
- [x] 对齐 component 顺序、canonical filtering、`--all`、`--expand`、`--flat`、
  statement/context/MLS rendering、数值与地址范围解析及确定性排序。
- [x] 对齐 help/version、running-policy discovery、verbose/debug load/query 日志、
  argparse/semantic error、stdout/stderr/退出码和 broken pipe 行为。
- [x] 增加产品自有的 SELinux/Xen synthetic fixtures、unit/integration tests；开发工作区
  的 37-case legacy 差分矩阵逐字节比较 stdout、stderr 和退出码并全部通过。

### M4：`sediff`

- [x] 所有跨 policy identity 使用 canonical name/semantic value，不比较 policy-local
  numeric ID。
- [x] 实现 property、symbol、common/class、user/MLS level、default 和 typebounds diff。
- [x] 实现 TE/xperm、RBAC、MLS range-transition 和 constraint semantic diff。
- [x] AV diff 展开 source/target attribute、合并重复 rules，并移除已由无条件 rule
  覆盖的 conditional permissions。
- [x] 实现全部 SELinux labeling diff，包括双 context 的 netifcon。
- [x] 对齐所有 component option、`-A`、`-T`、固定顺序、`--stats`、默认全量模式、
  help/version、verbose/debug、错误通道和确定性输出。
- [x] 产品 integration tests 覆盖全部 option 和默认模式；开发工作区 64-case legacy
  matrix（含完整 fixture、冗余 AV、verbose 和错误路径）逐字节通过。

### M5：`sedta` 与 `seinfoflow`

- [x] 在 owned `Policy` 上实现 domain-transition graph；标准转移校验
  `transition`、`execute`、`entrypoint` 与 `setexec`/`type_transition` 的完整组合，
  动态转移校验 `dyntransition` 与 `setcurrent`。
- [x] 建图时展开 source/target attribute，保留关联规则，并支持排除 domain 与
  entrypoint；无 raw/native policy 数据进入 graph crate。
- [x] 实现 forward/reverse immediate transitions、全部 shortest paths、限深 simple
  paths、limit、full rule rendering、statistics 和确定性枚举顺序。
- [x] 对齐 help/version、显式/running policy、verbose/debug、参数/分析错误、空结果、
  stdout/stderr/退出码和 broken pipe；`--output_file` 已接入可选 Graphviz `dot`，
  缺少后端时保持 4.7.1 当前环境的错误契约。当前机器未安装 `dot`，PNG 成功路径仍需
  在带 Graphviz 的 CI/环境验证。
- [x] 产品自有 synthetic fixture 与 graph/CLI tests 通过；开发工作区 37-case legacy
  matrix 逐字节比较 stdout、stderr 和退出码并全部通过，真实 1.9 MiB `policy` 的
  `init` 查询和 4025-node/5855-edge 统计也逐字节一致。
- [x] 实现独立 permission-map parser，并将 LGPL-2.1-only 的 4.7.1 默认映射作为
  `setools-graph` 数据资产嵌入发布包；运行时不依赖 legacy SETools，`-m/--map`
  仍可加载用户提供的替代映射。
- [x] information-flow graph 只消费 immutable owned `Policy`：展开 source/target
  attribute，以 `r`/`w`/`b`/`n`/`u` 映射生成有向边，合并贡献 rules 并取最大权重，
  忽略 self-flow 与非 allow rule。
- [x] 实现 minimum-weight/exclude/Boolean subgraph、forward/reverse immediate flow、
  全部 shortest paths、限深 simple paths、full rule rendering、limit、statistics、
  running policy、兼容日志/错误和可选 Graphviz PNG。未指定 `-b` 时保留条件两侧，
  `-b default` 或显式赋值时按 policy 默认值/override 裁剪。
- [x] 产品自有 permission map、policy fixture、5 个 graph unit tests 和 2 个 CLI
  integration tests 通过；开发工作区 55-case legacy matrix 的 stdout、stderr、status
  逐字节通过（只归一化动态 timestamp 和 legacy PermissionMap 对象地址）。真实
  1.9 MiB `policy` 的 `init` 前三条 flow 与 4123-node/945061-edge 统计逐字节一致。

### M6：`sechecker` 与结构化输出

- [x] 新增 LGPL-2.1-only `setools-checker`，配置解析、registry、检查语义和 typed
  debug trace 与 GPL CLI report/rendering 边界分离。
- [x] 支持 `empty_typeattr`、`assert_te`、`assert_rbac`、`ro_execs` 和 `ro_kmods`；
  strict/lenient symbol validation、expect/exempt expansion、disable reason 和 failure
  count 均按 4.7.1 语义处理。
- [x] 对齐 INI section 顺序与 DEFAULT inheritance、help/version、report/summary、UTC
  时间、`-o/--output_file`、running policy、verbose/debug、配置/加载错误和 0/1/2/3
  退出码。
- [x] 产品自有 checker policy、pass/fail/invalid configs 和 4 个 CLI integration tests
  覆盖五种 check type、缺失预期、禁用、失败汇总和文件输出。
- [x] 外层 44-case legacy matrix 覆盖 pass/fail、upstream module fixtures、DEFAULT、
  参数/配置/加载错误、verbose/debug 和输出文件；除 UTC/debug timestamp 及 Python
  randomized permission `frozenset` repr 顺序外逐字节比较并全部通过。真实 1.9 MiB
  `policy` 的 `init` source exemption check 与 legacy 同为 PASSED。
- [x] ADR 0002 冻结结构化输出 v1 的 schema/version、单文档 stdout、文本错误模型和
  CLI 共存规则；normative command-specific schema 位于产品仓库内。
- [x] `sesearch --json` 覆盖 TE/xperm、RBAC、MLS、全部 query criterion、空结果和标准
  JSON escaping；默认文本和冻结 help 不变，verbose/debug 仍只写 stderr。
- [x] `seinfo --json` 覆盖 typed statistics、全部显式 query criterion、SELinux/Xen
  component section、expand/flat/all 和空 section；默认文本/help/error 不变。
- [x] `sediff --json` 覆盖全部 38 个 component、显式空 component、默认 all、完整
  added/removed/modified counts 与 `--stats` count-only 行为；直接消费 semantic diff
  结果，不解析兼容文本，默认文本/help/error 不变。
- [x] `sedta --json` 覆盖 forward/reverse direct transition、shortest/all paths、limit、
  exclude、full typed rule provenance、typed graph statistics 和空结果；默认文本/help/
  error/Graphviz 契约不变。
- [x] `seinfoflow --json` 覆盖 forward/reverse direct flow、shortest/all paths、weight、
  limit/exclude、permission-map 来源、Boolean 三态、full contributing rules、typed graph
  statistics 和空结果；默认文本/help/error/Graphviz 契约不变。
- [x] `sechecker --json` 覆盖五类 check、pass/fail/disabled、failure summary、canonical
  TE/RBAC rule evidence、missing expectations、writable-file evidence 和配置路径；有
  findings 时仍输出完整 JSON 并保持 status 1，默认文本/help/error/output-file 契约不变。
- [x] ADR 0003 冻结 CLI 发布资产契约：六份 binary 直接使用的 product-owned frozen
  help 同时是公开 option metadata 的唯一来源；隐藏的附加 `--json` 由生成器显式补入，
  不改变兼容 help/parser。
- [x] 无第三方依赖的 `setools-xtask` 可确定性生成并逐字节检查 6 个 man1 page 以及
  Bash、Zsh、Fish completion，共 24 个 committed release asset；CI、README 和 release
  checklist 均接入 drift check。

### 首个 portable release

- [x] native bridge 与默认构建彻底移除 libselinux，动态 binary 的直接 native 依赖
  只剩 libsepol；PCRE2 不再进入传递依赖。
- [x] `SETOOLS_LIBSEPOL_STATIC_ROOT` 支持显式 static libsepol prefix，同时保留发行版友好
  的 pkg-config dynamic source build。
- [x] `scripts/build-portable-release.sh` 固定 libsepol 3.11 官方 source URL/SHA-256，
  构建 x86_64 GNU/Linux static PIE，并拒绝任何含 ELF `NEEDED` 的产物。
- [x] portable archive 包含六个 stripped binary、README、license、man/completion、
  build info、per-file checksum、libsepol 原始 tarball，以及带 locked vendored Cargo
  dependencies 的 setools-rs corresponding source。
- [x] 15 MiB archive 已在全新目录解包：外层 checksum、包内全部 39 个文件、六个
  `--version`、六个 ELF linkage 检查全部通过；`seinfo`/`sesearch` 成功加载当前
  1.9 MiB policy。相同 archive 也在禁网、read-only Debian trixie container 中成功
  用 `seinfo` 加载该 policy。
- [x] ADR 0004 记录 dynamic/static 模式、支持范围、license/source 与 C parser 风险。

## 后续里程碑

- [x] M4：`sediff` semantic diff。
- [x] M5：`sedta` 与 `seinfoflow` graph analysis。
- [~] M6：六个 CLI 的兼容范围、command-specific JSON v1、completion 和 man page
  均已完成；仅余 Python binding、MCP、GUI 的后续集成边界决策。
- [~] M7：独立 `setools-policy-binary` 已实现零 FFI/unsafe 的 bounded metadata parser；
  完整 symbol/rule/context model、fuzzing 和 CLI cutover 尚未完成。

## 当前验证基线

在 standalone repository 中应通过：

```text
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p setools-xtask -- check
cargo run -p setools-policy-binary --example policy-header -- /path/to/policy
python3 scripts/benchmark-cli.py --list
cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
scripts/build-portable-release.sh --policy /path/to/policy
```

最近一次实现验证：workspace 87 tests、Clippy `-D warnings`、release 六个 binary
build、24 个 generated asset 的 byte-exact check、benchmark manifest list 和六份
man1 `groff -man` check 均通过；六份 Fish completion 已生成，但当前机器没有 Fish
runtime 可执行 syntax check。本次重新执行 44-case `sechecker`、64-case `sesearch`、
37-case `seinfo`、64-case `sediff`、37-case `sedta` 和 55-case `seinfoflow` 全部 legacy
差分矩阵，均通过。默认动态六 binary 只含 libsepol 和 GNU system runtime，不含
libselinux/PCRE2；portable 六 binary 均无 ELF `NEEDED`。六个 normative JSON schema
均可由标准 JSON parser 读取；真实 1.9 MiB
`policy` 的 `sechecker --json` init source exemption check 可解析并返回 1 个 passed
check、0 failures。ASan/UBSan 在关闭 leak detection 后覆盖 bridge unit 与四个真实
policy load tests；LeakSanitizer 在当前 ptrace sandbox 中不可运行，仍需普通 shell/CI
执行既有 sanitizer job。

性能基线：真实 policy 的 7 个默认场景各 1 次 warm-up、3 次采样；Rust 相对 legacy
在 6 项更快且 7 项 peak RSS 都更低。indirect `sesearch` 为 14.0x，`seinfoflow` graph
为 12.8x 且 Rust peak RSS 约 224.4 MiB、legacy 约 714.1 MiB；`sediff-selected` 为
0.84x，是默认场景中唯一较慢项。原始数据、硬件和哈希见 `docs/PERFORMANCE.md`。

下一最小工作包：在纯 Rust parser 中实现 version/target compatibility table selection
和第一个 symbol-table family，增加 count/allocation limits 与 libsepol snapshot 差分；
在完整 owned model parity 前不接入 CLI。

## 发布未关闭项

- [x] 六个 CLI 的 4.7.1 兼容范围已完成。
- [x] 生成 shell completion。
- [x] 生成 man page。
- [~] portable artifact 固定并实测 libsepol 3.11，外层 pinned 3.9 完整测试仍保留；
  product CI 的正式 3.9/latest/main matrix 尚未建立。
- [~] 7 个默认场景的性能和峰值内存基线已记录；manual `sediff-full` 尚未完成。
- [ ] library API 稳定后决定 crates.io publication。
- [x] x86_64 Linux portable archive 包含 license、man/completion、dependency/build info、
  checksums 与 corresponding source，且六个 binary 均无 ELF `NEEDED`。

## 更新规则

每次实现会话结束前更新本文件，只记录本仓库自身可验证的状态。开发工作区中的
legacy oracle、差分 harness 或临时工具链不属于本仓库依赖，也不写入发布要求。
