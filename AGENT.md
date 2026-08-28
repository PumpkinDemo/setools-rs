# SETools Rust 重写：跨会话任务说明

## 任务

本仓库用 Rust 分阶段实现名称兼容的独立 binary：`sesearch`、`seinfo`、`sediff`、
`sedta`、`seinfoflow` 和 `sechecker`。

CLI 兼容目标是 SETools 4.7.1。新格式或 API 只能作为附加能力引入，不能破坏既有
参数、默认行为、stdout、stderr 和退出码。

## 每次会话开始时

依次阅读：

1. 本文件。
2. `docs/RUST_REWRITE_PROGRESS.md`。
3. `docs/RUST_REWRITE_DESIGN.md`。
4. 当前工作包涉及的 crate 和 Rust 测试。

先检查实际文件、Git 状态和测试结果，不要只依赖旧会话描述。

## 仓库边界

- 本目录是可单独克隆、构建、测试和发布的产品仓库。
- 不得依赖父目录或任意 legacy SETools Python/Cython 源码树。
- legacy 实现只能在仓库外作为开发参照或 oracle，不能进入 Cargo 构建图、
  `include_str!`、运行时路径、默认测试路径或发布包。
- 本仓库可包含 Rust 自身的 unit/integration tests 和对应的 synthetic fixtures。
- 普通 Cargo 命令使用标准 `target/`。

## 当前交接点

- M1 workspace、C bridge 和 owned policy model 已完成。
- M2 `sesearch` 已完成：TE/xperm/conditional/filename、RBAC、MLS、running-policy、
  verbose/debug、错误处理和确定性输出。
- M3 `seinfo` 已完成：统计摘要、所有 symbol/context/constraint/default/labeling
  component、SELinux/Xen 两种 target、statement expansion、flat 输出、platform
  validation、running-policy、日志和错误处理均已接通。
- `seinfo` 的 owned snapshot 包含 common/class permissions、role authorized types、
  users/MLS、constraints/defaults、policy capabilities 和全部 labeling contexts；native
  pointer 不离开 loader。
- 产品仓库包含独立 SELinux/Xen synthetic policy fixtures 和 Rust integration tests。
  开发工作区的 legacy 差分矩阵当前 37 个 case 全部逐字节通过，但不属于产品依赖。
- M4 `sediff` 已完成：全部 symbol/property/default/bounds、TE/xperm、RBAC、MLS、
  constraint 和 SELinux labeling component 均支持 added/removed/modified semantic diff，
  同时支持显式 selection、`-A`、`-T`、`--stats` 和无 component 参数的全量模式。
- `setools-diff` 的跨 policy key 只使用 canonical name/semantic value，不比较 numeric
  ID；AV diff 会展开 attribute、合并重复 grant，并扣除已由无条件规则覆盖的 conditional
  permission。产品仓库有独立双策略 fixture 和 integration tests。
- 外层开发工作区的 `sesearch` 64-case、`seinfo` 37-case、`sediff` 64-case legacy
  matrix 均逐字节通过，但它们不属于产品依赖。
- M5 `sedta` 已完成：标准/动态 domain-transition graph、attribute expansion、
  domain/entrypoint exclude、forward/reverse、shortest/all paths、full/stats/limit、
  running policy、日志和错误契约均已实现；产品自有 fixture/tests 与外层 37-case
  legacy matrix 通过。
- M5 `seinfoflow` 已完成：产品内置独立默认 permission map，weighted directed graph
  支持 attribute expansion、weight/exclude/Boolean subgraph、forward/reverse、
  shortest/all paths、full/stats/limit、running policy、日志和错误契约；产品 fixture/
  tests 与外层 55-case legacy matrix 通过，真实 `policy` 的 4123-node/945061-edge
  统计一致。
- M6 `sechecker` 兼容范围已完成：新增 LGPL `setools-checker`，INI registry 支持
  `empty_typeattr`、`assert_te`、`assert_rbac`、`ro_execs`、`ro_kmods`，CLI 已对齐
  report/summary、disable、`-o`、verbose/debug、配置/加载错误和退出码。产品自有
  policy/config fixtures 与 integration tests 通过；外层 44-case matrix 逐字节通过，
  真实 `policy` 的 `init` source exemption check 与 legacy 同为 PASSED。
- M6 `sesearch` structured-output v1 已完成：ADR 0002 与 normative JSON Schema 冻结
  envelope、版本、成功/空结果、文本错误模型和 CLI coexistence；隐藏的附加
  `--json` 不改变默认输出或冻结 help。产品 tests、外层 64-case matrix 和真实
  `policy` JSON parse 均通过。
- M6 `seinfo` structured-output v1 已完成：typed statistics 与全部 SELinux/Xen
  component section 使用稳定 ID，query 记录 all/expand/flat/explicit criteria；产品
  tests、外层 37-case matrix 和真实 `policy` JSON parse 均通过。
- M6 `sediff` structured-output v1 已完成：全部 38 个 component 直接消费 canonical
  semantic diff，记录双 policy、query、added/removed/modified counts 与明细；显式空
  component、默认 all 和 `--stats` 均已冻结。产品 tests、外层 64-case matrix 和真实
  `policy` JSON parse 均通过。
- M6 `sedta` structured-output v1 已完成：typed transition/path results 覆盖正反向、
  shortest/all paths、limit/exclude、full rule provenance、graph statistics 与空结果；
  `--json` 和 Graphviz `--output_file` 明确互斥。产品 tests、外层 37-case matrix 和真实
  `policy` JSON parse 均通过。
- M6 `seinfoflow` structured-output v1 已完成：weighted flow/path results 覆盖正反向、
  shortest/all paths、limit/exclude、permission-map 来源、Boolean 三态、full contributing
  rules、graph statistics 与空结果；`--json` 和 Graphviz `--output_file` 明确互斥。产品
  tests、外层 55-case matrix 和真实 `policy` JSON parse 均通过。
- M6 `sechecker` structured-output v1 已完成：typed check results 覆盖五类 registry、
  pass/fail/disabled、summary、canonical rule/missing/writable-file evidence；clean/status 0
  与 findings/status 1 都输出完整 JSON，配置/运行错误保持文本。产品 tests、外层
  44-case matrix 和真实 `policy` JSON parse 均通过。
- M6 completion/man-page 发布配套已完成：ADR 0003 规定六份 frozen help asset 为
  binary 与生成器共享的公开 CLI metadata；dependency-free `setools-xtask` 生成并检查
  6 个 man1 page 与 Bash/Zsh/Fish completion，共 24 个 committed asset。隐藏的
  `--json` 由生成器显式补入，兼容 help/parser 不变。
- M0 CLI performance contract 已冻结：`benchmarks/cli-v1.toml` 定义 7 个默认场景和
  manual `sediff-full`，stdlib-only `scripts/benchmark-cli.py` 在 Linux 用 `wait4(2)`
  记录 wall time/peak RSS。真实 1.9 MiB policy 的 Rust raw baseline 位于
  `docs/benchmarks/2026-08-27-cli-v1-rust.json`；legacy adapter/results 只在外层。
- 默认 7 场景中 Rust 相对 legacy 在 6 项更快且全部更省 peak RSS；manual full diff
  在当前 managed environment prolonged analysis 后收到 SIGKILL，原因尚不能归因。
- native backend 已移除 libselinux：running-policy discovery 由安全 Rust 实现，bridge
  ABI 6 只链接 libsepol；默认动态 binary 不再传递依赖 PCRE2。
- x86_64 Linux portable release 默认构建 pure Rust static PIE：
  `scripts/build-portable-release.sh` 不检查、下载、编译或链接 libsepol，并拒绝任何 ELF
  `NEEDED`。`--native-libsepol` 是保留的 static compatibility flavor；它固定并校验
  libsepol 3.11，随包带对应 source。两种 archive 都包含六个 binary、license、
  man/completion、校验清单和 setools-rs corresponding source。ADR 0004 记录边界。
- GitHub tag release 自动化位于 `.github/workflows/release.yml`：push 与 Cargo package
  version 精确对应的 `v*` tag 后，workflow 先在 Fedora 完整验证 workspace，再构建默认
  pure Rust static archive 并创建/更新同名 GitHub Release；只为 publish job 授予
  `contents: write`。不要在 release workflow 中引入父目录、legacy oracle 或默认 native
  dependency。
- M7 已完成全部八个 symbol family：独立、零 unsafe/FFI 的
  `setools-policy-binary` 实现 version 15..=35 的 SELinux/Xen header、compatibility
  table、前置 ebitmap、common、object-class、role、type、user、Boolean、sensitivity 与
  category parser；新增 role
  dominates/authorized-types/bounds、type/attribute flavor、alias、permissive、typebounds，
  user bounds/MLS range、MLS alias/category set，并覆盖 v20..=23 隐式 attribute gap。
  可独立重建的 role/user/Boolean/sensitivity/category owned model 和 type 的主名/flavor/
  alias/permissive/bounds 已与 libsepol 差分。AVTAB 与 conditional rule body 也已完成：
  覆盖 v15..=19 merged record、v20+ compact record、standard/type/xperm rule、Boolean
  postfix 及 true/false branch，并在产品 fixture 和真实 policy 上逐条匹配 libsepol。
  RBAC role transition/allow 与 filename transition 也已完成，覆盖 v15..=25 隐式
  process/domain class、v26+ 显式 class、v25..=32 expanded filename record 和 v33+
  compressed bitmap。共享 security context、全部 SELinux/Xen object-context family、
  genfs table、MLS range transition、policy capability 与全部尾部 `type_attr_map` 也已
  完成；named attribute concrete expansion 与 libsepol 一致，并兼容 v20..=23 无名
  attribute gap。`PureRustPolicyLoader` 已重建完整 immutable `Policy`；产品
  SELinux/Xen、filename、RBAC、MLS fixture 及当前真实 policy 的 full owned snapshot 与
  libsepol 语义一致，真实 policy 精确消费至 EOF。strict EOF/oversize、exhaustive
  truncation/bit-mutation tests 与独立 cargo-fuzz target 已有。parser retained allocation
  与完整 owned reconstruction 共用 conservative logical budget，涵盖 model container、
  string、nested data、B-tree name index 和 v20..=23 temporary attribute expansion；
  `native-libsepol` 是 opt-in compatibility feature。默认 binary 用 pure Rust loader；
  native feature 下 `SETOOLS_POLICY_BACKEND` 支持 `libsepol`、`rust`、`pure-rust`，六个
  product CLI fixture 和 selected real-policy command 的双 backend parity 已验证。
- 六个 CLI 的 command-specific JSON v1 与发布文档资产均已完成；M6 尚未整体关闭，
  只剩 Python binding、MCP、GUI 的后续集成边界决策。M7 已完成：allocation lifecycle、
  cargo-fuzz coverage run、可选 backend 与 product/real-policy parity 均已记录。当前
  M7/M8 与 pure portable-release packaging 均已完成：pure Rust loader 已是默认 binary，
  libsepol bridge 为 opt-in compatibility feature。后续工作处理长期 coverage run、full
  `sediff` 性能诊断或新的兼容差异；不回退正常 source build 对 native library 的零依赖。
  full `sediff` 性能问题仍保留为独立 backlog。

常用验证命令：

```text
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p setools-xtask -- check
python3 scripts/benchmark-cli.py --list
cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
scripts/build-portable-release.sh --policy /path/to/policy
scripts/build-portable-release.sh --native-libsepol --policy /path/to/policy
```

## 不可破坏的设计约束

- 当前 CLI loader 使用小型 C bridge 读取 libsepol 内部数据；普通 Rust 代码不得直接
  遍历 `policydb_t`、`hashtab_t`、`avtab_t` 或 `ebitmap_t`。纯 Rust parser 必须在
  独立 crate 按 binary format 安全解码，不得复制 C layout/unsafe traversal。
- raw handle、FFI pointer 和常规 `unsafe` 必须封装在 `setools-sepol`。
- native policy 只用于加载；复制为 immutable owned `Policy` 后立即释放。
- query、diff、graph 和 CLI 层不得依赖 libsepol pointer、布局或 lifetime。
- internal relation 使用 policy-local typed ID；跨 policy diff 使用 canonical name 和
  semantic value，不比较 numeric ID。
- CLI parsing、query、semantic result 和 rendering 分层，不能用 `Debug` 充当文本协议。
- 输出必须确定性排序，不得依赖 hash-map iteration 或 worker 完成顺序。
- 不要过早引入 async 或未经 benchmark 证明的索引/并行化。
- libsepol parser 仍是 C，不得宣称加载链路端到端 memory safe。

偏离上述约束前先写 ADR 并更新设计文档。

## License 与依赖

- library crate 保持 LGPL-2.1-only 边界。
- CLI program 与测试保持 GPL-2.0-only 边界。
- 新增依赖前确认用途、license 和维护状态。
- `native-libsepol` feature 通过 `pkg-config` 动态链接 libsepol，并用 `cc` 编译 bridge；
  默认 pure Rust build 不需要它，也不把 bindgen/libclang 作为要求。
- 只有 `--native-libsepol` portable release 使用经 SHA-256 固定的 libsepol
  source/static archive；更新版本或 digest 前必须检查 license、ABI、完整测试和真实
  policy。默认 pure Rust portable release 不含该 source 或 native bridge。

## 每次会话结束时

1. 运行与风险相称的 fmt、lint 和 test。
2. 更新 `docs/RUST_REWRITE_PROGRESS.md`。
3. 写清完成项、未完成项和下一最小工作包。
4. 只有达到退出条件才能将里程碑标为完成。
5. ABI 或 schema 决策需补充测试和 ADR/设计文档。

交接信息必须让后续会话只靠本仓库继续，不能依赖父目录或聊天历史。
