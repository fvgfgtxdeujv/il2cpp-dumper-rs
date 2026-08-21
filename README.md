# il2cpp-dumper-rs + DumpCS Filter

> **Il2Cpp 逆向工具链** — 源码可审计的 Rust 引擎 + Kotlin 筛选 App

---

## 仓库结构（双仓）

```
il2cpp-dumper-rs/           # Rust 引擎仓库（本目录）
├── src/                    # 引擎源码（49 个 .rs 文件）
├── jniLibs/                # 预编译 .so（arm64-v8a + armeabi-v7a）
├── dotnetdll-main/         # GPL 依赖源码（DummyDll 输出用）
├── Cargo.toml / Cargo.lock
└── README.md               # 引擎构建说明

app/                        # Android App 仓库（DumpCS Filter）
├── src/main/java/          # Kotlin/Java 应用源码
├── src/main/jniLibs/       # 引用引擎预编译 .so
├── build.gradle.kts
└── README.md
```

两个仓库**物理分离**，各自独立提交、独立发布。

---

## 组件说明

### il2cpp-dumper-rs（Rust 引擎）

- **语言**：Rust 2024 edition
- **版本**：v0.7.0
- **源码**：公开可审查（MIT 许可），二进制分发方式不公开
- **JNI 符号**：4 个（detectFormat / dumpIl2Cpp / getDefaultConfig / initCrashHandler）
- **metadata 支持**：v16–v110，含 v106.1/v107/v108/v110
- **解密链**：XOR 系列 + Mfuscator v27-37

### DumpCS Filter（Android App）

- **包名**：`com.dumpcs.filter`
- **版本**：V10.1
- **语言**：Kotlin + Jetpack Compose（Material 3）
- **功能**：dump.cs 智能筛选、树形浏览、音乐播放、AI 聊天
- **依赖引擎**：预编译 `librodroid_il2cppdumper.so`（引擎仓不公开二进制获取方式）

详见 [app/README.md](app/README.md)。

---

## 快速开始

### 安装 App APK

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

### 构建 App APK

```bash
cd app
./gradlew assembleDebug
```

---

## 技术栈

| 层面 | 技术 |
|---|---|
| 引擎（Rust） | il2cpp-dumper-rs v0.7.0，JNI 绑定 4 个符号 |
| App UI | Jetpack Compose + Material 3 + Navigation Compose |
| App 存储 | Room + DataStore Preferences |
| App 音频 | MediaPlayer + MediaMetadataRetriever |
| 解析 | 流式逐行解析（Reader.forEachLine） |

---

## License

- **引擎源码**：MIT
- **App 源码**：MIT
- **引擎包含 GPL 组件**：`dotnetdll`（GPL-3.0+）用于 DummyDll 输出；预编译 .so 已包含此组件
- **参考实现**：Cpp2IL（MIT）、Il2CppInspectorRedux（AGPL v3，仅参考，代码未复制）、Il2CppInspectorPlugins（AGPL v3，仅参考）

---

*il2cpp-dumper-rs · DumpCS Filter · 为热爱逆向的你而生*
