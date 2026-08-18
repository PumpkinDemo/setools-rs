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
- 其他五个 binary 仍是 scaffold。
- 当前主线是 M3 `seinfo`。

常用验证命令：

```text
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p setools-cli --bin sesearch
```

## 不可破坏的设计约束

- 使用小型 C bridge 读取 libsepol 内部数据；普通 Rust 代码不得直接遍历
  `policydb_t`、`hashtab_t`、`avtab_t` 或 `ebitmap_t`。
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
- 默认通过 `pkg-config` 动态链接 libsepol/libselinux，并用 `cc` 编译 bridge；不把
  bindgen/libclang 作为默认构建要求。

## 每次会话结束时

1. 运行与风险相称的 fmt、lint 和 test。
2. 更新 `docs/RUST_REWRITE_PROGRESS.md`。
3. 写清完成项、未完成项和下一最小工作包。
4. 只有达到退出条件才能将里程碑标为完成。
5. ABI 或 schema 决策需补充测试和 ADR/设计文档。

交接信息必须让后续会话只靠本仓库继续，不能依赖父目录或聊天历史。
