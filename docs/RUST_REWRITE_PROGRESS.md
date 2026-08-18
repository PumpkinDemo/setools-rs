# SETools Rust 重写进度

最后更新：2026-08-18（Asia/Shanghai）

当前阶段：M2 `sesearch`、M3 `seinfo` 已完成；下一阶段为 M4 `sediff`

CLI 兼容目标：SETools 4.7.1

## 项目边界

- 本仓库独立构建、测试和发布。
- 实现不依赖 legacy SETools Python/Cython 源码或运行环境。
- native 依赖仅为 libsepol、libselinux 及编译 C bridge 所需的 C toolchain。
- `checkpolicy` 只用于编译 Rust integration-test 的 synthetic policy fixtures。
- Cargo 使用标准 `target/` 输出目录。

## 已完成

### M1：workspace、bridge 与 owned model

- [x] 六 crate workspace 与六个 binary entry point。
- [x] project-owned C bridge、opaque native handle 和 Rust RAII 封装。
- [x] policy metadata、type/attribute/alias、class/permission、Boolean/conditional、
  TE/xperm、filename transition、role/RBAC 和 MLS range transition snapshot。
- [x] native policy 在 loader 返回 owned `Policy` 前释放。
- [x] raw libsepol 类型与常规 `unsafe` 不离开 `setools-sepol`。
- [x] running-policy discovery 使用 libselinux current-policy path 和版本化 fallback。

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

## 后续里程碑

- [ ] M4：`sediff` semantic diff。
- [ ] M5：`sedta` 与 `seinfoflow` graph analysis。
- [ ] M6：`sechecker`、结构化输出、completion 和 man page。
- [ ] M7：可选纯 Rust binary-policy parser；不阻塞首个发布。

## 当前验证基线

在 standalone repository 中应通过：

```text
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p setools-cli --bin sesearch --bin seinfo
```

最近一次实现验证：workspace 24 tests、Clippy `-D warnings`、release
`sesearch`/`seinfo` build 以及 37-case `seinfo` legacy 差分矩阵通过。当前工作区的真实
policy 还对 statistics、每个 component、`--expand` 和 `--all` 做了逐字节对比。

下一最小工作包：进入 M4，先定义 `sediff` canonical cross-policy keys 和 properties/
simple-symbol diff，再逐步加入 types、roles、users、classes/commons、MLS、contexts 与
rule semantic diff。

## 发布未关闭项

- [ ] 完成 `seinfo` 与 `sediff` 后再声明首个多工具兼容版本。
- [ ] 生成 man page。
- [ ] 建立支持的 libsepol version CI matrix。
- [ ] 记录性能和峰值内存基线。
- [ ] library API 稳定后决定 crates.io publication。

## 更新规则

每次实现会话结束前更新本文件，只记录本仓库自身可验证的状态。开发工作区中的
legacy oracle、差分 harness 或临时工具链不属于本仓库依赖，也不写入发布要求。
