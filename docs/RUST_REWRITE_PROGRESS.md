# SETools Rust 重写进度

最后更新：2026-08-29（Asia/Shanghai）

当前阶段：首个 x86_64 Linux portable 版本已可发布；纯 Rust binary-policy parser
已完成 header、全部 symbol family、TE/conditional、RBAC、filename-transition 与
SELinux/Xen labeling、MLS range-transition、policy capability 和尾部 attribute map

CLI 兼容目标：SETools 4.7.1

## 项目边界

- 本仓库独立构建、测试和发布。
- 实现不依赖 legacy SETools Python/Cython 源码或运行环境。
- 默认 source build 是纯 Rust，不依赖 libsepol、libselinux、PCRE2、C toolchain 或
  `pkg-config`；`native-libsepol` feature 仅用于 compatibility comparison。
- 默认 x86_64 Linux portable archive 使用 pure Rust loader 构建 static PIE，目标系统无需
  安装 libsepol、libselinux、PCRE2、libgcc 或特定 glibc shared object；可选 native
  compatibility archive 仍固定 libsepol 3.11。
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
- [x] `scripts/build-portable-release.sh --native-libsepol` 固定 libsepol 3.11 官方
  source URL/SHA-256，构建 x86_64 GNU/Linux static PIE，并拒绝任何含 ELF `NEEDED` 的
  产物。
- [x] 初版 native portable archive 曾包含六个 stripped binary、README、license、
  man/completion、build info、per-file checksum、libsepol 原始 tarball，以及带 locked
  vendored Cargo dependencies 的 setools-rs corresponding source。
- [x] 该初版 15 MiB archive 已在全新目录解包：外层 checksum、包内全部 39 个文件、六个
  `--version`、六个 ELF linkage 检查全部通过；`seinfo`/`sesearch` 成功加载当前
  1.9 MiB policy。相同 archive 也在禁网、read-only Debian trixie container 中成功
  用 `seinfo` 加载该 policy。
- [x] ADR 0004 记录 dynamic/static 模式、支持范围、license/source 与 C parser 风险。
- [x] `scripts/build-portable-release.sh` 默认输出
  `setools-rs-4.7.1-linux-x86_64.tar.gz`：不检查、下载、编译或链接
  libsepol，仍要求六个 binary 均为无 ELF `NEEDED` 的 static PIE。2026-08-29 使用当前
  1.9 MiB policy 完成 binary-only smoke test；12 MiB archive 的普通文件数精确为 6，
  checksum 为 `b3740d08df3470058c0038bf2a589d743dfe06124d10715f7fbd3a57ad145035`。
  当前 pure/native binary archive 都只包含 `bin/` 下六个 stripped executable，外部
  `.sha256` 单独发布。`--native-libsepol` 保留原 static native compatibility build，
  libsepol source URL/version/digest 继续固定在 release script 中。
- [x] `.github/workflows/release.yml` 在 `v*` tag push 时自动运行：先于 Fedora
  container 完整验证 workspace，再在 x86_64 Ubuntu 构建/smoke-test default pure Rust
  archive、检查 checksum，并以只授予 `contents: write` 的 `GITHUB_TOKEN` 创建或更新
  同名 GitHub Release。workflow 会拒绝与 Cargo package version 不一致的 tag；重跑只会
  覆盖 archive 与 `.sha256` 两个 asset。CI 的 portable artifact job 同步改为 pure Rust
  archive name/path。
- [x] release workflow 同时提供 `workflow_dispatch` 的必填 `tag` 输入。若 tag 早于
  workflow、或 release 只显示 GitHub 自动生成的 source archives，可在 Actions 页面指定
  既有 `v*` tag 手动补跑；它 checkout 该 tag、再次验证 version，并以 `--clobber` 补上
  binary archive 与 checksum，而不新建第二个 release。
- [x] binary-only archive 不再运行 `cargo fetch`/`cargo vendor`，fresh GitHub runner 只需
  下载实际 pure Rust build 使用的依赖；optional native build dependency 与源码不会被
  无意义地复制进默认 release 包。
- [x] 默认 archive、外部 checksum、CI artifact 与 GitHub Release asset 统一使用简短名称
  `setools-rs-4.7.1-linux-x86_64.tar.gz`；可选 native compatibility archive 使用不会覆盖
  默认包的 `setools-rs-4.7.1-linux-x86_64-native.tar.gz`。

## 后续里程碑

- [x] M4：`sediff` semantic diff。
- [x] M5：`sedta` 与 `seinfoflow` graph analysis。
- [~] M6：六个 CLI 的兼容范围、command-specific JSON v1、completion 和 man page
  均已完成；仅余 Python binding、MCP、GUI 的后续集成边界决策。
- [x] M7：独立 `setools-policy-binary` 已实现零 FFI/unsafe 的 bounded parser：精确
  校验 SELinux/Xen version compatibility table，解析并验证前置 ebitmap、common
  permission、object-class、role、type、user、Boolean、sensitivity 与 category 全部 symbol
  family；覆盖 inherited/local permission、
  constraint/validatetrans postfix、v29+ type set、versioned defaults、role bitmap/bounds、
  type/attribute/alias/permissive/typebounds、user bounds/MLS range、MLS alias/category set，
  以及 v20..=23 implicit attribute gap。AVTAB/conditional rule body 已覆盖 v15..=19
  merged record、v20+ compact record、standard/type/xperm rule、Boolean postfix 与
  true/false branch。RBAC 与 filename transition 已覆盖 v15..=25 隐式 class、v26+
  显式 class、v25..=32 expanded record 和 v33+ compressed bitmap。共享 security
  context、全部 SELinux/Xen object-context family、genfs table、MLS range transition、
  前置 policy-capability bitmap 与每一行尾部 `type_attr_map` 已覆盖。named attribute
  concrete expansion 与 libsepol 一致，v20..=23 unnamed attribute gap membership 也会
  保留；`PureRustPolicyLoader` 已将 parser-owned representation 重建为完整 immutable
  `Policy`。产品 SELinux/Xen、filename、RBAC、MLS fixture 与当前真实 policy 的 full
  owned snapshot 均和 libsepol 语义一致，真实 policy 精确消费至 EOF。严格 EOF/oversize
  拒绝、truncation/bit-mutation property test 和独立 cargo-fuzz target 已完成。parser
  retained allocation 与完整 `Policy` reconstruction 共用一个 conservative logical
  budget，覆盖 model 容器、string、嵌套数据、B-tree name index 和 v20..=23 temporary
  attribute expansion；serialized input 有独立 byte limit。`to_policy` 与
  `PureRustPolicyLoader` 均会保留 typed `LimitExceeded` error。2026-08-28 使用六个
  product/real-policy seed 完成一轮 60 秒 instrumented coverage run（5,838 inputs、279
  new corpus entries、524 MiB peak RSS、无 parser error；当前 sandbox 不支持
  LeakSanitizer，故仅该环境以 `detect_leaks=0` 运行）。native feature 下
  `SETOOLS_POLICY_BACKEND` 可选 `libsepol`、`rust` 或 `pure-rust`；产品 integration test 对六个 binary
  的 status/stdout/stderr 做双 backend byte-exact 比较。真实 1.9 MiB policy 的 selected
  `sesearch`、`seinfo`、`sediff`、`sedta`、`seinfoflow` 成功 JSON 输出以及有效
  `sechecker` config 的 exit status/JSON 也逐字节一致。`sedta` graph edge 已按 canonical
  source/target name 排序，避免 backend-specific ID 改变输出顺序。M8 已将 pure-Rust
  backend 设为 default，native bridge 保留为 opt-in feature。
- [x] 受当前 managed runner 的单命令 wall-time/memory 限制，额外以真实 policy 的
  256 KiB 前缀作为临时 seed，运行六个 `--sanitizer none`、各 `-runs=2000` 的 coverage
  batch；六批均以 status 0 完成，未新增 `fuzz/artifacts/` 文件。临时 corpus 全部留在
  `/tmp`，不进入发布仓库；完整 real-policy 的长期 address-sanitizer campaign 仍适合在
  资源更充足的 CI/普通 shell 执行。
- [x] M8：native-independent CLI build。`native-libsepol` 已成为 opt-in compatibility
  feature，普通 `cargo build -p setools-cli --bins` 的 dependency graph 不含
  `setools-sepol`/libsepol。pure build 提供 Rust-owned running-policy discovery/timestamp
  helper，六个 binary 的 34 个 integration tests、24 个 lib tests、Clippy 与真实 policy
  byte-exact comparison 均通过；显式 native feature 的 35 个 integration tests（含 dual
  backend parity）与 Clippy 也通过。默认 loader 为 pure Rust。
- [x] M8 release 收尾：默认 portable script 已与默认 loader 对齐，产物不含 native
  bridge/libsepol；native static archive 只能由 `--native-libsepol` 显式请求。2026-08-28
  用当前 1.9 MiB policy 实际打包成功，archive checksum 为
  `e5942f0b367a9d5954339f57c5ab9c8baa77867f2cd0c1c39ed1e28830d3bd20`（不纳入仓库）。

## 当前验证基线

在 standalone repository 中应通过：

```text
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p setools-xtask -- check
cargo run -p setools-policy-binary --example policy-header -- /path/to/policy
cargo run -p setools-policy-binary --example policy-prefix -- /path/to/policy
python3 scripts/benchmark-cli.py --list
cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
scripts/build-portable-release.sh --policy /path/to/policy
scripts/build-portable-release.sh --native-libsepol --policy /path/to/policy
```

最近一次实现验证：默认 workspace 111 tests（另有 1 个显式 real-policy ignored test）、
以及 `native-libsepol` feature 的 35 个 CLI integration tests（包含 dual-backend
parity）均通过；
Clippy `-D warnings`、release 六个 binary
build、24 个 generated asset 的 byte-exact check、benchmark manifest list 和六份
man1 `groff -man` check 均通过；六份 Fish completion 已生成，但当前机器没有 Fish
runtime 可执行 syntax check。本次重新执行 44-case `sechecker`、64-case `sesearch`、
37-case `seinfo`、64-case `sediff`、37-case `sedta` 和 55-case `seinfoflow` 全部 legacy
差分矩阵，均通过。默认动态六 binary 不含 libsepol、libselinux/PCRE2；native feature
动态 binary 只含 libsepol 和 GNU system runtime；default pure-Rust 与 optional native
portable 六 binary 均无 ELF `NEEDED`。六个 normative JSON schema
均可由标准 JSON parser 读取；真实 1.9 MiB
`policy` 的 `sechecker --json` init source exemption check 可解析并返回 1 个 passed
check、0 failures。ASan/UBSan 在关闭 leak detection 后覆盖 bridge unit 与四个真实
policy load tests；LeakSanitizer 在当前 ptrace sandbox 中不可运行，仍需普通 shell/CI
执行既有 sanitizer job。

性能基线：真实 policy 的 7 个默认场景各 1 次 warm-up、3 次采样；Rust 相对 legacy
在 6 项更快且 7 项 peak RSS 都更低。indirect `sesearch` 为 14.0x，`seinfoflow` graph
为 12.8x 且 Rust peak RSS 约 224.4 MiB、legacy 约 714.1 MiB；`sediff-selected` 为
0.84x，是默认场景中唯一较慢项。原始数据、硬件和哈希见 `docs/PERFORMANCE.md`。

本次纯 Rust slice 验证：20 个 parser unit tests 覆盖 v15/v20/v23/v24/v30/v35 versioned layout、
v20..=23 implicit attribute gap、继承/本地 permission、constraint postfix、named-type
bitmap、role/type/user/Boolean/MLS、alias/bounds/permissive、default 与资源上限；产品
自有 `seinfo.conf` 的 common、完整 `ObjectClass`、role、user、Boolean、sensitivity、
category、`ConstraintRule` 和 `DefaultRule` owned model，以及 type 的主名/flavor/alias/
permissive/bounds 均与 libsepol snapshot 相同。新增 AVTAB/conditional 单元覆盖旧/新
布局、dontaudit 反码、type rule、ioctl xperm、postfix 和条件分支；产品 `seinfo.conf`
及 filename fixture 的所有非 filename TE rule 与 conditional owned model 均逐条匹配
libsepol，并覆盖 ioctl/nlmsg xperm。当前 1.9 MiB `policy`（version 30）可由纯 Rust
prefix loader 读取其 TE/conditional 段至 byte offset 1654591，
得到 5 个 common、107 个 class、4 个 role、4591 个 type/attribute 主值（4132 type、
459 attribute）、1 个 type alias、1 个 permissive、1 个 user、0 个 Boolean、1 个
sensitivity、1024 个 category、313 个声明 permission、89 个 constraint 和 0 个
default；112585 个非 filename TE rule 与 libsepol owned model 的多重集完全一致。
新增 RBAC/filename slice 后，产品 `rbac.conf` 的 26 条 RBAC rule、filename fixture 的
RBAC/filename owned model 也完全一致，并覆盖旧格式首条生效重复规则、v15 隐式
`process` class、v33+ 多 datum bitmap 的 disjoint/default 校验。当前真实 policy 的
0 条 RBAC rule 与 94 条 v30 filename transition 均逐条匹配 libsepol，prefix 读取至
byte offset 1657688。新增 context/labeling slice 后，共享 context 解码会校验 concrete
type、user/role 与 direct/deferred-attribute role/type authorization、MLS dominance/
category/user range；SELinux 九 family、
Xen 五/六 family、v24/v30 IOMEM 宽度、IPv4/IPv6/InfiniBand network-order address、
fs_use/protocol/range 及 genfs duplicate/class 均有 bounded 读取。产品 `seinfo.conf` 和
`xen.conf` 的 supported labeling model 与 libsepol 完全相同；当前真实 policy 的
1531 条 labeling rule 也逐条匹配。新增 tail slice 后，v21+ 显式 class 与 v19..=20
隐式 `process` class 的 MLS range transition 均会做 type/class/range/duplicate validation；
产品 `mls.conf` 的 38 条规则逐条匹配。policy capability bit 会验证并保留 canonical
number，全部 `type_attr_map` row 会反建 concrete expansion，并最终确认 labeling context
的 role/attribute authorization；产品 type expansion/policy capabilities 与 libsepol
相同。当前真实 policy 含 4 个 policy capability、0 条 MLS range transition、10733 个
named-symbol attribute membership，完整解析 1947827 bytes，恰好等于文件大小。

完整 owned reconstruction 已实现：`BinaryPolicyPrefix::to_policy` 与
`PureRustPolicyLoader` 会构造全部 type/class/role/Boolean/conditional、TE/RBAC/MLS rule
及 `SeinfoData`。v20..=23 缺失的 attribute 主名会按 native 规则生成为
`@ttr##########`，并从 containing membership 反建 concrete member。产品
`seinfo.conf`、`filename-transition.conf`、`rbac.conf`、`mls.conf`、`xen.conf` 及当前
1.9 MiB real policy 均通过 full-model differential comparison；native hash order
不稳定的 rule/labeling collection 按多重集比较。

完整 parser 现在拒绝 byte limit 以上的直接输入和 serialization 后的 trailing data；文件
loader 会读取上限加 1 字节，可靠区分 exact-limit 与 oversized file。单元测试穷举完整
synthetic policy 的每一个 truncation，并对每个 byte 的 8 个单 bit mutation 执行 bounded
parse，成功解析的 mutation 继续构造 owned `Policy`。独立、非发布的 `fuzz/` workspace
锁定 `libfuzzer-sys 0.4.13`，header/full parser/owned reconstruction target 已通过 stable
build、Clippy 和 10000-run 非 coverage smoke；正式 coverage-guided campaign 已以六个
seed 运行 60 秒，另有六个有限 2000-run prefix batch 均成功结束。allocation budget 已覆盖
complete owned reconstruction 的整个 load lifecycle，默认 CLI 已接入 pure Rust loader。
下一最小工作包是资源更充足环境中的 full-policy coverage run、full `sediff` 性能诊断或
新的兼容差异。

## 发布未关闭项

- [x] 六个 CLI 的 4.7.1 兼容范围已完成。
- [x] 生成 shell completion。
- [x] 生成 man page。
- [~] optional native portable artifact 固定并实测 libsepol 3.11，外层 pinned 3.9 完整
  测试仍保留；product CI 的正式 3.9/latest/main matrix 尚未建立。默认 pure Rust archive
  不受该 matrix 约束。
- [~] 7 个默认场景的性能和峰值内存基线已记录；manual `sediff-full` 尚未完成。
- [ ] library API 稳定后决定 crates.io publication。
- [x] x86_64 Linux portable archive 只包含 `bin/` 下六个 stripped binary，且均无 ELF
  `NEEDED`；archive 的 `.sha256` 单独发布，license、文档与 source 由 release tag 提供。

## 更新规则

每次实现会话结束前更新本文件，只记录本仓库自身可验证的状态。开发工作区中的
legacy oracle、差分 harness 或临时工具链不属于本仓库依赖，也不写入发布要求。
