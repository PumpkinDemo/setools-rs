# SETools Rust 重写进度

最后更新：2026-08-18（Asia/Shanghai）

当前阶段：M2 `sesearch` 已完成；下一工作包为 M3 `seinfo`

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

## 当前工作包：M3 `seinfo`

- [ ] 补齐 symbol、context、constraint、default 和 labeling owned model。
- [ ] 实现 component query、计数、statement rendering 和 expansion 选项。
- [ ] 对齐 help/version、verbose/debug、错误通道和退出码。
- [ ] 增加 Rust unit/integration test。

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
cargo build --release -p setools-cli --bin sesearch
```

最近一次实现验证：workspace 17 tests、Clippy `-D warnings` 和 release build 通过；
从仅含本仓库文件、没有相邻 legacy source 或 compatibility harness 的临时导出副本
重复执行 workspace test 与 release build，同样通过。

## 发布未关闭项

- [ ] 完成 `seinfo` 与 `sediff` 后再声明首个多工具兼容版本。
- [ ] 生成 man page。
- [ ] 建立支持的 libsepol version CI matrix。
- [ ] 记录性能和峰值内存基线。
- [ ] library API 稳定后决定 crates.io publication。

## 更新规则

每次实现会话结束前更新本文件，只记录本仓库自身可验证的状态。开发工作区中的
legacy oracle、差分 harness 或临时工具链不属于本仓库依赖，也不写入发布要求。
