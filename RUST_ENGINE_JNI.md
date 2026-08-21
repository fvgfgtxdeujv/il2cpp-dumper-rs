# il2cpp-dumper-rs 引擎 JNI 绑定层选型与实现方案

> 状态：阶段 1–2 已完成，release .so 已替换；宿主 cargo check 零错误零警告，16 个测试全部通过
> 关联：`BUILD.md` / `DEV_GUIDE.md` / `app/src/main/java/com/rodroid/il2cppdumper/utils/DumperBridge.java`
> 场景：将预编译 `librodroid_il2cppdumper.so` 替换为 il2cpp-dumper-rs **源码构建**产物，为 Rust 引擎补写 JNI 绑定层，保持 App 侧 Java 协议不变。

---

## 1. 背景与目标

- 现有 `librodroid_il2cppdumper.so` 为预编译产物，JNI 符号导出 4 个方法，Java 侧由 `DumperBridge.java`（`System.loadLibrary("rodroid_il2cppdumper")`）按符号名解析调用：

| Java 方法 | JNI 导出符号 |
|---|---|
| `String detectFormat(String)` | `Java_com_rodroid_il2cppdumper_utils_DumperBridge_detectFormat` |
| `String dumpIl2Cpp(String, String, String, String, DumperCallback)` | `Java_com_rodroid_il2cppdumper_utils_DumperBridge_dumpIl2Cpp` |
| `String getDefaultConfig()` | `Java_com_rodroid_il2cppdumper_utils_DumperBridge_getDefaultConfig` |
| `void initCrashHandler(String)` | `Java_com_rodroid_il2cppdumper_utils_DumperBridge_initCrashHandler` |

- il2cpp-dumper-rs（0.7.0）公开源码**不含 JNI 层**（`lib.rs` 仅有 10 行模块声明），是纯 CLI 应用。因此需要自行编写 Rust JNI 绑定层，把 `main.rs` 的 `run()` 核心流程库化为可编程 API，再通过 JNI 暴露给 Java。
- 目标：产出由项目源码构建、可审计的 `librodroid_il2cppdumper.so`，Java 侧协议零改动。

---

## 2. 候选库调研

### 2.1 jni / jni-rs（基础绑定库）

- **仓库**：`jni-rs/jni-rs`（GitHub）
- **crate**：`jni`，最新稳定版 **0.22.4**（2026-03 更新，持续活跃）
- **数据**：crates.io 总下载量约 **1.6 亿**，Rust 生态 JNI 事实标准
- **许可**：Apache-2.0 / MIT 双许可
- **能力**：
  - 直接导出 `#[no_mangle] pub extern "system" fn Java_...` 实现 Java native 方法（JVM 与 Android 均支持）
  - 提供 `JNIEnv` 完整 API：字符串转换、查找类/方法、调用 Java 方法、全局/局部引用、异常检查、附加线程（`JavaVM::attach_current_thread`）
  - 与现有符号名解析完全兼容：`#[no_mangle]` 导出的符号名可精确控制为 `Java_com_rodroid_il2cppdumper_utils_DumperBridge_*`
- **示例（0.22.x）**：

```rust
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;

#[no_mangle]
pub extern "system" fn Java_com_example_Demo_hello(
    env: JNIEnv, _class: JClass, input: JString,
) -> jstring {
    let input: String = env.get_string(&input)
        .expect("Couldn't get java string").into();
    let output = env.new_string(format!("Hello, {}!", input))
        .expect("Couldn't create java string!");
    output.into_raw()
}
```

- **结论**：作为纯 JNI 绑定基础，功能完整、维护活跃、生态成熟。

### 2.2 robusta（自动化宏）

- **仓库**：`rust-android/robusta`（作者 mdkozar）
- **crate**：`robusta` 在 crates.io **不可用**——现存包是 2018 年注册的无关占位（`0.0.0`，"Coffea robusta"，仅 1 个版本），**只能通过 git 依赖引入**
- **维护状态**：实质更新停滞（约 2022 年后无活跃迭代）
- **能力**：
  - `#[bridge]` 宏包裹模块，`#[object]` 声明 Java 类映射、`#[export]` 标记导出方法、`#[callback]` 标记回调对象
  - 自动生成 `JNI_OnLoad` + `RegisterNatives` 注册表，省去手写符号名与签名串
  - 类型自动映射（`JavaString`、自定义 object 等），减少样板代码
- **风险**：
  - 注册方式依赖 `JNI_OnLoad`，与"精确符号名"要求不同（符号由宏生成，无法保证与现有 `Java_com_..._DumperBridge_*` 一一对应）
  - crates.io 无发布版本，只能 git 依赖，供应链与版本锁定不便
  - 回调/复杂签名支持有限，遇到边界场景仍需回退到 jni-rs 手动处理

### 2.3 droid-wrap（高级封装）

- **仓库**：`mzdk100/droid-wrap`（GitHub）
- **crate**：`droid-wrap`，最新稳定版 **0.4.1**（2025-10 更新）
- **数据**：crates.io 总下载量约 **3.3 万**（小众，Context7 信誉 Medium）
- **能力**：
  - 在 jni-rs 之上封装 Android 特定 API（`Activity`、`TextView`、`Vibrator` 等），消除 `unsafe`
  - `#[android_main]` 宏提供 Rust 端 App 入口；`XxxImpl::from_fn` 用闭包实现 Java 接口回调（`RunnableImpl`、`View_OnClickListenerImpl`、`TextWatcherImpl` 等）
  - Cargo feature 按需裁剪（`android_app` / `android_widget` / `android_view` / `java_lang` 等）
- **场景匹配度**：
  - 目标场景是"给现有 Kotlin/Compose App 的 .so 提供 4 个 native 方法"，**不需要操作 Android UI API**
  - `#[android_main]` 面向"整个 App 用 Rust 写"的架构，与现有 Kotlin 项目结构冲突
  - 回调封装基于动态代理（Proxy），适合 UI 监听器，与 dump 引擎的日志/输入回调协议（`DumperCallback` 接口）不直接对齐
- **结论**：与本次需求错位，仅作参考。

---

## 3. 横向对比

| 维度 | jni / jni-rs | robusta | droid-wrap |
|---|---|---|---|
| crates.io 可用版本 | 0.22.4（稳定） | 不可用（git 依赖） | 0.4.1 |
| 下载量 / 维护活跃度 | 1.6 亿 / 活跃（2026 仍更新） | 停滞（约 2022） | 3.3 万 / 一般 |
| 符号名精确控制 | 支持（`#[no_mangle]`） | 不支持（宏生成 + RegisterNatives） | 依赖 jni-rs 底层，间接支持 |
| 回调支持 | 手动 `call_method`，完全可控 | 宏 `#[callback]` 有限 | 面向 UI 监听器（动态代理） |
| 线程安全 | `GlobalRef` + 显式 attach，成熟 | 依赖 jni-rs | 依赖 jni-rs |
| 适用场景 | 通用 JNI 绑定（本次需求） | 快速样板，小项目 | 整 App Rust 化 / UI 操作 |
| 许可 | Apache-2.0/MIT | MIT/Apache-2.0 | 需查证（小众） |

---

## 4. 选型结论

**采用 `jni`（jni-rs 0.22.x）作为绑定层基础库。** 理由：

1. **符号名精确匹配**：现有 App 通过 `System.loadLibrary` + 符号名解析调用，jni-rs 的 `#[no_mangle] pub extern "system" fn` 可直接导出 `Java_com_rodroid_il2cppdumper_utils_DumperBridge_*` 四个同名符号，Java 侧零改动。
2. **轻量匹配**：需求仅需基础 JNI 能力（参数转换、回调调用、异常抛出），jni-rs 正是该粒度；robusta/droid-wrap 的额外能力（UI 封装、宏生成）在此场景无用且引入不确定性。
3. **可靠性**：1.6 亿下载、持续维护、文档完备；robusta crates.io 无版本且维护停滞，droid-wrap 场景错位且样本少。

---

## 5. 绑定层实现方案（基于 jni-rs 0.22）

### 5.1 Cargo.toml 改动

```toml
[lib]
name = "rodroid_il2cppdumper"
crate-type = ["cdylib", "rlib"]

[dependencies]
jni = "0.22"
```

- `name = "rodroid_il2cppdumper"` 保证产出 `librodroid_il2cppdumper.so`，与 `System.loadLibrary("rodroid_il2cppdumper")` 匹配。
- `cdylib` 为 Android 需要的动态库类型；`rlib` 保留单元测试能力。

### 5.2 库化 dump 流程（前置改造）

新增 `src/dump_engine.rs`，把 `main.rs` 的 `run()` 抽取为可编程 API（**已实现**，见末尾「实现状态」）：

```rust
pub trait DumpSink {
    fn log(&mut self, msg: &str);              // 引擎日志（默认空实现）
    fn progress(&mut self, msg: &str);         // 阶段进度（默认空实现）
    fn warn(&mut self, msg: &str);             // 警告（默认空实现）
    fn success(&mut self, msg: &str);          // 成功信息（默认空实现）
    fn request_input(&mut self, prompt: &str, default: Option<&str>) -> Option<String>;
    // 默认返回 None = 跳过（dump 基地址、CR/MR 手动地址、Fat Mach-O 架构选择）
}

pub struct DumpSummary {
    pub output_dir: String,
    pub generated_files: Vec<String>,
    pub elapsed_secs: f64,
    pub metadata_version: f64,
    pub metadata_decryption: Option<String>,
    pub unity_version: Option<String>,
    pub format: String,
}

pub fn dump_with_sink(
    binary_path: &str, metadata_path: &str, output_dir: &str,
    config: &Config, sink: &mut dyn DumpSink,
) -> Result<DumpSummary>;
```

- 替换掉 `clap`/`dialoguer`/`console`/`indicatif` 交互；`spinner` → `sink.progress`，`print_*` → `sink.log`，`prompt_*` → `sink.request_input`。
- 整个流程同步执行（确认源码未实际使用 rayon 并行），JNI 回调无跨线程问题。

### 5.3 四个 JNI 导出（`src/jni_bridge.rs`）

```rust
use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, GlobalRef, JValue};
use jni::sys::jstring;

// 1) 格式检测：先查 metadata magic（0xFAB11BAF）→ "Metadata"，
//    再查 ELF/PE/MachO/FatMachO/NSO/WASM magic → "ELF64"/"ELF32"/"PE"/...
#[no_mangle]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_detectFormat(
    env: JNIEnv, _class: JClass, path: JString,
) -> jstring { /* ... */ }

// 2) 执行 Dump：解析 configJson → Config，调 dump_with_sink，
//    成功返回输出目录路径（Java 侧 _outputPath.value = result），
//    失败返回 "Error: <msg>"（Java 侧 startsWith("Error") 判定失败）
#[no_mangle]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_dumpIl2Cpp(
    env: JNIEnv, _class: JClass,
    binary: JString, metadata: JString, out_dir: JString, config_json: JString,
    callback: JObject,
) -> jstring { /* ... */ }

// 3) 默认配置：serde_json::to_string(&Config::default())（camelCase，与 DumperConfig 兼容）
#[no_mangle]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_getDefaultConfig(
    env: JNIEnv, _class: JClass,
) -> jstring { /* ... */ }

// 4) crash handler：std::panic::set_hook 写 crash 日志到指定路径
#[no_mangle]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_initCrashHandler(
    env: JNIEnv, _class: JClass, log_path: JString,
) { /* ... */ }
```

### 5.4 回调桥接（DumperCallback）

- Java 接口：`onLog(String)`、`onRequestInput(String) -> String`。
- JNI 侧（`dumpIl2Cpp` 内，同步执行）：`JniSink` 持 `GlobalRef`（`env.new_global_ref` 保护整个 dump 期间 callback 存活），用 `env.call_method` 按名称+签名调用（**已实现**）：

```rust
// JniSink 实现（src/jni_bridge.rs）
impl DumpSink for JniSink<'_, '_> {
    fn log(&mut self, msg: &str) {
        let jmsg: JObject = self.env.new_string(msg).unwrap().into();
        let _ = self.env.call_method(
            &self.callback,                       // &GlobalRef: AsRef<JObject>
            "onLog",                              // 方法名
            "(Ljava/lang/String;)V",              // 签名串
            &[JValue::Object(&jmsg)],
        );
    }
    fn request_input(&mut self, prompt: &str, default: Option<&str>) -> Option<String> {
        let jprompt: JObject = self.env.new_string(prompt).unwrap().into();
        let out = self.env.call_method(
            &self.callback, "onRequestInput",
            "(Ljava/lang/String;)Ljava/lang/String;",
            &[JValue::Object(&jprompt)],
        ).ok()?;
        let obj = out.as_obj()?;                  // JValue -> &JObject
        if obj.is_null() { return default.map(String::from); }  // 跳过
        let jstr = unsafe { JString::from_raw(obj.clone().into_raw() as jstring) };
        let text = self.env.get_string(&jstr).ok()?.to_string_lossy().into_owned();
        if text.is_empty() { default.map(String::from) } else { Some(text) }
    }
}
```

- 异常处理：`call_method` 返回 `Err` 时按"用户取消/无输入通道"处理（走 default 或跳过），不中断 dump；引擎内所有可失败路径通过 `Result` 返回错误字符串。
- 跨线程（后续若引入 rayon）：需在 worker 内 `env.get_java_vm()?.attach_current_thread()`，回调经 `GlobalRef` 调用——当前同步方案不需要，但 `GlobalRef` 已就位，接口上保留扩展能力。

### 5.5 与 Java 侧协议的兼容性要点

| 契约 | 现有行为（预编译 .so） | 新实现 |
|---|---|---|
| `detectFormat` 返回值 | 格式字符串（含 Metadata） | 增加 metadata magic 判断返回 `Metadata`，二进制返回 `ELF64/ELF32/PE/Mach-O/...` |
| `dumpIl2Cpp` 返回值 | 输出目录路径；失败返回 Error 开头文本 | 返回 `DumpSummary.output_dir`；失败 `Error: <msg>` |
| `getDefaultConfig` | JSON，App 侧兜底若干 key | 返回完整 `Config::default()`（camelCase），覆盖所有兜底 key |
| 回调 | `onLog` / `onRequestInput` | 完全等价 |
| crash handler | 写 native crash 日志 | `panic::set_hook` 写指定路径 |

---

## 6. 构建与替换流程

1. 安装工具链（需用户确认）：Rust（`rustup`）+ Android NDK（cargo-ndk 或 NDK 独立 toolchain）。
2. 交叉编译：

```bash
# 方式一：cargo-ndk（推荐，自动设置 NDK 环境）
cargo ndk -t arm64-v8a -o <out> build --release

# 方式二：NDK 独立 toolchain + CC 环境变量
```

3. 产物替换：`libarm64-v8a.so` → `app/src/main/jniLibs/arm64-v8a/librodroid_il2cppdumper.so`。
4. 验证：`readelf --dyn-syms` 确认 4 个 `Java_com_rodroid_il2cppdumper_utils_DumperBridge_*` 符号存在；App 内跑一次完整 dump 流程回归。

---

## 7. 风险与注意事项

- **JNI 符号大小写**：包名/类名含下划线，符号名必须逐字符一致（`Java_com_rodroid_il2cppdumper_utils_DumperBridge_*`），`#[no_mangle]` + `extern "system"` 保持原样导出，禁止编译器改名。
- **签名串准确性**：`onRequestInput` 返回 `String`，签名必须是 `(Ljava/lang/String;)Ljava/lang/String;`，写错会导致 `NoSuchMethodError`。
- **panic 边界**：Rust panic 跨越 FFI 边界是 UB，`dumpIl2Cpp` 内所有可能失败路径必须捕获并转为错误返回值，另设 `panic::catch_unwind` 兜底（release profile 已从 `abort` 改为 `unwind`，否则 catch_unwind 无效）。
- **进度回调频率**：`Il2CppDecompiler::decompile` 的进度闭包直接接 `sink.progress`，回调过密时由 Java 侧节流。
- **`detectFormat` 语义**：Java 侧对二进制与 metadata 共用同一 native 方法，新实现必须同时识别 metadata magic，否则 `detectMetadata` 显示"格式错误"。
- **lib 名与符号**：`Cargo.toml` 的 `[lib] name` 决定 .so 文件名，`cdylib` 决定导出方式，二者缺一不可。

---

## 8. 实现状态（阶段 1–2 完成，引擎仓已拆分）

2026-08-21 已全部落地（代码位于 `il2cpp-dumper-rs/src/`，宿主 `cargo check --all-targets` 零错误零警告，`cargo test` 16 个测试通过）：

| 文件 | 状态 | 说明 |
|---|---|---|
| `src/dump_engine.rs` | 已实现 | `DumpSink` trait（5 方法全部带默认实现）、`NullSink`、`DumpSummary`（7 字段）、`dump_with_sink()` 全流程；解密管线含 Mfuscator 分支 |
| `src/jni_bridge.rs` | 已实现 | 4 个 `#[unsafe(no_mangle)] extern "system"` 导出；`JniSink`（`Global<JObject>` + `call_method` 按名+签名调用） |
| `src/lib.rs` | 已更新 | 追加 `pub mod dump_engine; pub mod jni_bridge; pub mod mfuscator;` |
| `Cargo.toml` | 已更新 | `[lib] name = "rodroid_il2cppdumper"` + `crate-type = ["cdylib", "rlib"]`；`jni = "0.22"` 依赖；release `panic = "unwind"` |
| `src/il2cpp/structures.rs` | 已更新 | v106.1/107/108/110 结构体扩展；IndexWidths 动态宽度推导 |
| `src/il2cpp/enums.rs` | 已更新 | `Il2CppMetadataUsage::normalize_usage` 新增 |
| `src/il2cpp/metadata.rs` | 已更新 | known_versions 含 107/108/110；resolve_sub_version 106/107 分支；fake-v107 检测 |
| `src/mfuscator.rs` | 已实现 | Mfuscator v27-37 解密（try_fixup_mfuscator），2 个单元测试 |
| `jniLibs/arm64-v8a/librodroid_il2cppdumper.so` | 已交付 | 6.0MB，release + LTO + strip，4 个 JNI 符号验证通过 |
| `jniLibs/armeabi-v7a/librodroid_il2cppdumper.so` | 已交付 | 5.1MB，release + LTO + strip，4 个 JNI 符号验证通过 |
| `app/build.gradle.kts` | 已清理 | 移除 `buildRustEngine` 任务（引擎仓独立） |

**仓库拆分（2026-08-21）**：
- 引擎仓：`il2cpp-dumper-rs/`（独立 git 仓，含源码 + 预编译 .so）
- App 仓：`app/`（依赖引擎仓预编译 .so，不再包含 Rust 源码和编译任务）

---

## 9. 参考资料

- jni-rs 官方仓库：`https://github.com/jni-rs/jni-rs`（Apache-2.0/MIT，v0.22.4）
- jni crate 文档：`https://docs.rs/jni`
- robusta：`https://github.com/rust-android/robusta`（crates.io 无发布版本，git 依赖）
- droid-wrap：`https://github.com/mzdk100/droid-wrap`（v0.4.1，feature 门控 Android API 封装）
- il2cpp-dumper-rs：`/workspace/app/src/main/rust`（v0.7.0，MIT，已并入主项目作为 Rust 引擎）
