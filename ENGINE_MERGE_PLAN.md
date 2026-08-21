# 三引擎合并技术方案（il2cpp-dumper-rs × Il2CppInspectorRedux × Cpp2IL）

> 状态：阶段 2 完成，release .so 已交叉编译替换；阶段 3（P7–P12）待实施
> 关联：`RUST_ENGINE_JNI.md`（JNI 绑定层专项）、`BUILD.md` / `DEV_GUIDE.md`
> 场景：DumpCS Filter 的 dump 引擎由「预编译 .so + 卡密限制」改为「三项目 + 插件仓库合并、全部源码可控」：
> 主引擎 il2cpp-dumper-rs 从源码构建 .so 并集成；Il2CppInspectorRedux、Cpp2IL 与 Il2CppInspectorPlugins 以**功能映射移植**方式补足主引擎能力。

---

## 1. 背景与目标

- **主引擎**：`il2cpp-dumper-rs`（Rust 0.7.0，MIT）——现有 `librodroid_il2cppdumper.so` 的源码本体，但公开源码**不含 JNI 层**（`lib.rs` 仅 10 行模块声明），需自行补写绑定层并交叉编译（详见 `RUST_ENGINE_JNI.md`）。
- **合并对象 A**：`Il2CppInspectorRedux`（C#，AGPL v3）——桌面逆向工具，metadata 版本支持最新（到 v110）。
- **合并对象 B**：`Cpp2IL`（C#，MIT）——IL2CPP 转 .NET 反编译工具，能把原生代码反编译成**含真实 IL 的程序集**。
- **目标**：三引擎能力统一收口到 Rust 主引擎中，App 运行时只加载一个由源码构建的 .so；C# 项目以「参考实现 + 功能移植」方式贡献算法与结构差异，不引入 .NET 运行时。

---

## 2. 三引擎定位与现状

### 2.1 il2cpp-dumper-rs（Rust 主引擎）

| 维度 | 现状 |
|---|---|
| 二进制格式 | ELF / PE / Mach-O / Fat Mach-O / NSO / WASM |
| metadata 版本 | 16/17/19/20/21/22/24.x/27/29/31/33/35/38/39/104/105/106（**缺 106.1 细分、107、108、110**） |
| 输出 | dump.cs、script.json、il2cpp.h、il2cpp-functions.h、stringliteral.json、static_metadata.json、DummyDll（**无 IL 的占位程序集**）、generics_dump.txt、C++ scaffold、反汇编（iced-x86 / yaxpeax-arm） |
| 注册表定位 | ELF 段扫描 / 符号表 / ARM32 搜索模式、PE 符号表、Mach-O `__mod_init_func`、NSO/WASM 段扫描 |
| 解密 | metadata 内置 1/4/8 字节 XOR、滚动 XOR、位置相关 XOR、头部 XOR 试探 |
| 集成 | 需补 JNI 层（`RUST_ENGINE_JNI.md`） |

### 2.2 Il2CppInspectorRedux（C#，AGPL v3）

- 10 个子项目、302 个 C# 源文件，`net10.0`，版本 2026.2。
- **metadata 版本最全**：到 v110；核心是 `VersionedSerialization` 属性化版本机制（source generator 编译期展开版本分支），v38+ 用「基础版本号 + tag 字符串」编码动态索引宽度。
- 版本差异关键点（相对 Rust 引擎的增量）：
  - **v106.1**：`Il2CppMetadataUsage` 移除 `kMetadataUsageIl2CppType` 枚举值；`Il2CppMetadataRegistration` 新增 `AlwaysInitMetadataUsages*` 字段。
  - **v107**：结构与 v106.1 相同，但 Unity 6000.5 会「假升级」到 107——需用 vtable 第一条目解码验证真假，假则回退 106。
  - **v108**：最大分水岭——generic method 元数据、RGCTX、static cctors 从二进制搬进 global-metadata。Header 新增 9 个 section（`MethodSpecsOnGenericType`/`GenericMethodSpecsOnType`/`MethodSpecs`/`GenericMethodFunctionsDefinitions`/`GenericMethodFunctionsDefinitionsWithAdjustor`/`InvokerIndices`/`RgctxRanges`/`RgctxValues`/`StaticConstructorTypeIndices`）；`Il2CppMetadataRegistration` 移除 `GenericMethodTable`/`MethodSpecs`；`Il2CppCodeGenModule` 移除 `InvokerIndices`/`RgctxRanges`/`Rgctxs`/`StaticConstructorTypeIndices`；GenericInstIndex 等 5 个索引做动态宽度。
  - **v110**：Header 新增 `GeneratedMethodTypeInfos`/`GeneratedMethodTokens` 2 个 section；TypeDefinition/MethodDefinition/FieldDefinition/PropertyDefinition/EventDefinition 的 `Token` 字段移除。
- 反混淆：**仓库内置的只有格式处理**（ELF 重定位/NSO LZ4 解压/Mach-O FairPlay 检测/打包 PE）；XOR、Striped XOR、string encryption、Riot 重排序、miHoYo 等加密算法**在外部 `Il2CppInspectorPlugins` 插件仓库**（已克隆纳入，见 2.4）。
- 输出格式：C# stub、C++ scaffolding、反汇编器元数据（IDA/Ghidra/BinaryNinja 的 JSON+Python+C 头）、.NET shim DLL（dnlib）、VS 工程。
- ARM64 注册表定位：`Il2CppBinaryARM64.cs` 用 ADRP+LDR/ADD 指令解码扫描 `Il2CppCodegenRegistration`。

### 2.3 Cpp2IL（C#，MIT）

- 13 个子项目、427 个 C# 源文件；CLI 目标 net10.0；MIT 许可（LibCpp2IL 同为 MIT）。
- **metadata 版本**：v23–v108（**无 v33、无 v110**；v107 映射回 106/106.1）。版本细分映射集中在 `Il2CppMetadata.cs`（v24→24.1/24.15/24.2/24.3/24.4/24.5、v27→27.1/27.2、v29→29.1、v31→31.1、v106→106.1）。
- **核心差异化能力：`dll_il_recovery` 输出格式**——把原生指令反编译成**含真实 CIL 字节码的程序集**：
  - 管线：`MethodAnalysisContext.Analyze()`（原生指令 → ISIL → CFG → StackAnalyzer → SSA → 30+ 分析 pass → `IlGenerator.GenerateIl`）→ AsmResolver 写出 PE。
  - 反汇编器：Iced（x86）、Disarm（ARM64）、Capstone（ARMv7）、Wasm。
  - 对比 Rust 引擎的 DummyDll（仅结构、方法体是占位 stub），这是最大能力差距。
- 解密：内置 **Mfuscator 自动 XOR 解密**（`DeriveXorKey` 推导 key，`CyclicXorHeader`/`CyclicXor` 解 header 与字符串段，重建 metadata）；游戏特定混淆（如原神）无内置处理。
- 移植性评估（explore agent 结论）：
  - **高可移植**：LibCpp2IL 解析层（纯自定义二进制读取）、ISIL/CFG/SSA/分析 pass/IlGenerator 算法（纯托管无外部依赖）。
  - **瓶颈**：AsmResolver.DotNet（.NET 程序集写模型，Rust 生态无等价物，`dnfile` 只能读）——最终 IL 程序集写出环节需自研或换中间格式。

### 2.4 Il2CppInspectorPlugins（C#，AGPL v3，已纳入）

- **仓库**：`djkaty/Il2CppInspectorPlugins`，已克隆至 `/workspace/third_party/Il2CppInspectorPlugins`（624K，11 个 .cs 文件），**AGPL v3 许可**。
- **结构**：`Core`（4 个默认内置插件）+ `Loaders`（3 个加载器）+ `Examples`（4 个教程）。Beebyte-Deobfuscator 目录为空（README 有提及但无实现代码）。
- **核心算法清单**（可直接映射到 Rust）：

| 插件 | 算法 | 可移植性 |
|---|---|---|
| `Core/XOR-Decryptor` | **二进制文件级 XOR 解密**：.rodata 字节频率统计推导 key 候选；ARMv7/AArch64 指令特征半字节（bit 4-11 与 bit 28-31）推导 key；RLE + 直方图检测 striped 加密的 stripe size；按 stripe 解密 `.text`/`.rodata` | 高（纯字节运算；Rust 引擎目前只解密 metadata，不解密 libil2cpp.so 本身，此插件补齐二进制侧） |
| `Core/String-Decryptor` | **metadata 字符串 XOR 解密**：检测到字符串字典 key 缺失（null 终止符非 null 即被加密）时，用 null terminator 作为 XOR key 逐个解密 | 高（纯字节运算，直接接入现有 metadata 解析前） |
| `Core/API-Discovery` | **API export 名 ROT 解密**：ROT1-25 逐一尝试，匹配 `il2cpp_`/`_il2cpp_`/`__il2cpp_` 前缀 | 高（简单） |
| `Core/Binary-Metadata-Field-Reconstructor` | CodeRegistration/MetadataRegistration **混淆字段顺序重建**（启发式：指针连续性、区间、反转率等；仅支持 v19–24.1 旧版本） | 低（仅旧版本，启发式复杂，暂不移植） |
| `Loaders/miHoYo` | 整体依赖 **Windows 版 UnityPlayer.dll** 的 `DecryptMetadata`/`GetStringFromIndex`/`GetStringLiteralFromIndex`（LoadLibrary + 硬编码函数偏移），Android 不可行；但其中**原神 0x10 字节块 XOR** 独立可移植（固定 key `{0xAD,0x2F,0x42,0x30,0x67,0x04,0xB0,0x9C,0x9D,0x2A,0xC0,0xBA,0x0E,0xBF,0xA5,0x68}`，`step=(len>>14)<<6`，每 step 字节加密 0x10 字节）；另有 miHoYo metadata 判定法（magic 非法 + 末尾 0x4008 处 DWORD 自指）与 `MappedTypes.cs` 字段重排映射 | 部分（原神 XOR + 判定法可移植；DLL 依赖部分不移植） |
| `Loaders/guigubahuang` | **鬼谷八荒 metadata 减法解密**：从位置 21 起用 ASCII key 循环做减法（`bytes[pos] -= key[i % len]`），验证头 4 字节减 key 后等于 metadata magic；预设 key 表（0.8.1010/0.8.1012 两版） | 高（纯字节运算） |
| `Examples/StringLiterals-ROT` | 字符串字面量 ROT 解密（教程示例） | 中（示例性质） |
| `Examples/*` 其余 | 插件钩子/选项教程（Analytics、LoadPipeline、Options-And-Validation） | 不移植（Il2CppInspector 插件 API 机制，与 Rust 引擎无关） |

---

## 3. 能力对比矩阵

### 3.1 metadata 版本支持

| 版本 | il2cpp-dumper-rs | Il2CppInspectorRedux | Cpp2IL |
|---|---|---|---|
| 16–24.x | 有 | 有 | 有（24.x 细分最全） |
| 27/29/31 | 有 | 有 | 有（含 27.2/29.1/31.1） |
| 33 | 有 | 有 | 无 |
| 35/38/39 | 有 | 有 | 有 |
| 104/105/106/106.1 | 有（106 无 106.1 细分） | 有（含 106.1） | 有（含 106.1） |
| 107 | 无 | 有（真/假升级检测） | 有（映射回 106） |
| 108 | 无 | 有（大改） | 有 |
| 110 | 无 | 有 | 无 |

### 3.2 输出能力

| 输出 | il2cpp-dumper-rs | Il2CppInspectorRedux | Cpp2IL |
|---|---|---|---|
| dump.cs / C# stub | 有 | 有 | 有（diffable_cs） |
| C++ scaffolding | 有 | 有 | — |
| IDA/Ghidra/BinaryNinja 脚本 | 有（script.json + 内嵌脚本） | 有（JSON+Python+C 头） | — |
| dummy DLL | 有（占位） | 有（dnlib） | 有（dll_default/empty/throw_null） |
| **含真实 IL 的程序集** | **无** | — | **有（dll_il_recovery，最大差异）** |
| 静态字段元数据 / stringliteral | 有（static_metadata.json） | 有 | — |

### 3.3 解密/反混淆

| 能力 | il2cpp-dumper-rs | Il2CppInspectorRedux | Cpp2IL | Il2CppInspectorPlugins |
|---|---|---|---|---|
| metadata 常见 XOR（1/4/8 字节、滚动、位置相关） | 有（内置） | 插件 | — | 有（String-Decryptor，null 终止符作 key） |
| **二进制文件（libil2cpp.so）XOR / striped 解密** | **无** | — | — | **有（XOR-Decryptor，ARM 指令特征 + stripe 检测）** |
| API export 名 ROT 解密 | 无 | — | — | 有（API-Discovery） |
| Mfuscator XOR 自动推导 key | 无 | — | 有（内置） | — |
| 原神 0x10 字节块 XOR | 无 | 插件 | — | 有（miHoYo，独立可移植部分） |
| 鬼谷八荒减法解密（预设 key） | 无 | — | — | 有（guigubahuang） |
| 游戏特定加密（Arknights/CoD/FreeFire 等） | 无 | 插件 | — | 插件仓库无实现（README 提及但代码缺失/在别处） |

---

## 4. 合并策略总览

### 4.1 集成形态：JNI 绑定层 + 源码构建 .so

- il2cpp-dumper-rs 补写 `src/jni_bridge.rs`（jni-rs 0.22），保持 `Java_com_rodroid_il2cppdumper_utils_DumperBridge_*` 四个符号，`cargo ndk` 交叉编译 arm64-v8a，替换预编译 .so。
- 详见 `RUST_ENGINE_JNI.md`，本节不重复。

### 4.2 功能映射移植清单（C# → Rust，优先级排序）

| 编号 | 移植项 | 来源 | 许可 | 优先级 | 工作量 |
|---|---|---|---|---|---|---|
| P1 | metadata v107/v108/v110 支持（含 v107 假升级检测） | Il2CppInspectorRedux（结构差异）+ Cpp2IL（v107→106 映射参考） | 参考实现，自行编码 | 高 | 中 |
| P2 | metadata v106.1 细分（MetadataUsage 枚举变化、AlwaysInitMetadataUsages） | 两个 C# 项目 | 同上 | 高 | 小 |
| P3 | Mfuscator XOR 自动解密（DeriveXorKey + CyclicXor） | Cpp2IL | MIT（可直接参考） | 中 | 小 |
| P4 | LibCpp2IL 解析层与注册表定位算法参考（如 ARM64 ADRP+LDR 指令解码定位） | Cpp2IL + Il2CppInspectorRedux | MIT / 参考实现 | 中 | 中 |
| P5 | IL 恢复（dll_il_recovery：ISIL/CFG/SSA/分析 pass/IlGenerator） | Cpp2IL | MIT | 低（远期） | 极大 |
| P6 | dummy DLL 增强（更完整 stub 结构） | Cpp2IL dll_default | MIT | 低 | 中 |
| P7 | **二进制文件 XOR 解密**（.rodata 频率统计 + ARM 指令特征 + striped stripe 检测，解 .text/.rodata） | Il2CppInspectorPlugins `Core/XOR-Decryptor` | AGPL（参考实现） | 高 | 中 |
| P8 | **metadata 字符串 XOR 解密**（null 终止符作 key，检测 key 缺失） | Il2CppInspectorPlugins `Core/String-Decryptor` | AGPL（参考实现） | 中 | 小 |
| P9 | **API export 名 ROT 解密**（ROT1-25 匹配 il2cpp_ 前缀） | Il2CppInspectorPlugins `Core/API-Discovery` | AGPL（参考实现） | 中 | 小 |
| P10 | **原神 0x10 字节块 XOR**（固定 key + `step=(len>>14)<<6`）+ miHoYo metadata 判定法 | Il2CppInspectorPlugins `Loaders/miHoYo` | AGPL（参考实现） | 中 | 小 |
| P11 | **鬼谷八荒减法解密**（位置 21 起 key 循环减法 + 预设 key 表） | Il2CppInspectorPlugins `Loaders/guigubahuang` | AGPL（参考实现） | 低 | 小 |
| P12 | 字符串字面量 ROT 解密 | Il2CppInspectorPlugins `Examples/StringLiterals-ROT` | AGPL（参考实现） | 低 | 小 |

> 插件类移植项（P7–P12）统一接入 Rust 引擎的**解密管线**：现有 `try_decrypt_metadata`（metadata 文件级）之后按序尝试 P8/P10/P11 → 二进制加载阶段（`formats/*`）按序尝试 P7/P9 → dump 阶段 P12。

### 4.3 不移植项及理由

| 项 | 理由 |
|---|---|
| C# stub / C++ scaffolding / IDA/Ghidra/BinaryNinja 脚本 | Rust 引擎已有等价输出（script.json、C++ scaffold、内嵌脚本），重叠 |
| Il2CppInspectorPlugins 的 miHoYo UnityPlayer.dll 调用部分 | 依赖 Windows 版 UnityPlayer.dll（LoadLibrary + 硬编码偏移），Android 运行时不可行；仅取其独立算法（P10） |
| Il2CppInspectorPlugins 的字段顺序重建 | 仅支持 v19–24.1 旧版本且启发式复杂，与主引擎目标版本（Android 新版本）错位 |
| Redux 的 GUI / SignalR / Tauri 前端 | 桌面端架构，与 Android App 集成无关 |
| 把 C# 项目整体作为 .NET 运行时打进 App | 与「单一源码构建 .so」目标冲突，体积/架构成本高 |

---

## 5. 功能映射移植详单

> 编号与 4.2 清单一致。改造点：P1/P2 → `src/il2cpp/metadata.rs`；P3/P8/P10/P11 → 解密管线（`main.rs` 的 `try_decrypt_metadata` 扩展为多阶段解密链）；P4/P7/P9 → `src/formats/*`（二进制加载阶段）；P5/P6 → `src/output/*`；P12 → stringliteral 输出阶段。

### P1：metadata v107 / v108 / v110 支持

1. **known_versions 列表**追加 107、108、110；`Il2CppGlobalMetadataHeader` 的版本分支补齐：
   - v108：新增 9 个 section 字段；`Metadata` 结构新增对应数组（method_specs_on_generic_type 等）；解析时对 GenericInstIndex/GenericMethodIndex/MethodPointerTableIndex/InvokerTableIndex/AdjustorThunkIndex 做动态宽度 tag 计算。
   - v110：新增 2 个 section（GeneratedMethodTypeInfos/GeneratedMethodTokens）；5 个定义结构（Type/Method/Field/Property/Event Definition）在读取时跳过 Token 字段。
2. **v107 假升级检测**：读 header 后若 version_raw == 107，用 vtable 第一条目解码验证；失败回退 106。

参考文件（C# 侧）：
- `Il2CppInspector.Common/Next/Metadata/Il2CppGlobalMetadataHeader.cs`、`Next/MetadataVersions.cs`、`IL2CPP/Metadata.cs`
- `LibCpp2IL/Metadata/Il2CppMetadata.cs`（版本映射注释 185–213 行）

### P2：metadata v106.1 细分

- `MetadataVariant`/subversion 检测增加 106.1；`Il2CppMetadataUsage` 的 kMetadataUsageIl2CppType 枚举按 106.1 分支处理；MetadataRegistration 增加 AlwaysInitMetadataUsages 字段。

### P3：Mfuscator XOR 解密

- 移植 `Cpp2IL.Plugin.Mfuscator/MfuscatorSupportPlugin.cs` 的 `DeriveXorKey` / `CyclicXorHeader` / `CyclicXor` 逻辑到 `try_decrypt_metadata` 之后作为新增分支（在现有 XOR 试探全部失败时尝试）。

### P4：注册表定位增强（ARM64）

- 参考 `Il2CppInspector.Common/Architectures/Il2CppBinaryARM64.cs` 的 ADRP+LDR/ADD 指令解码扫描（`sweepForAddressLoads`），补充到 ELF 定位链（现有：段扫描 → 符号表 → ARM32 搜索模式之后）。

### P5：IL 恢复（远期）

- 拆分三个子阶段：
  1. 移植 LibCpp2IL 解析层（高可移植，纯二进制读取）。
  2. 移植 ISIL/CFG/SSA/分析 pass/IlGenerator 算法。
  3. 解决程序集写出瓶颈：自研 Rust 版 .NET 程序集写入器，或先输出中间表示（ISIL 序列化），由 PC 端 .NET 工具（原 Cpp2IL CLI）完成最终产出。
- 该功能产出物（含真实 IL 的 DLL）不适合直接在 Android App 内消费（需配套反编译器），建议定位为「PC 端增强输出」或二期能力。

### P6：dummy DLL 增强

- 参考 `Cpp2IL.Core/OutputFormats/AsmResolverDllOutputFormatDefault.cs` 的 stub 方法体生成策略，增强 `src/output/dummy_assembly_generator.rs` 的结构完整性（继承/泛型/自定义属性填充）。

### P7：二进制文件 XOR 解密（libil2cpp.so 侧）

- 参考 `Core/XOR-Decryptor/Plugin.cs`，在 `src/formats/elf.rs` 加载后、定位注册表之前执行：
  1. `.rodata` 前 1024 字节与整段做字节频率统计，取最频繁字节为 key 候选（区分 striped/full）。
  2. `.text` 前 256 个 dword 提取 ARM 指令特征半字节（ARMv7：bit 4-8 与 bit 28-31；AArch64：bit 8-12 与 bit 28-31），对比常见指令特征值推导 key。
  3. RLE + 直方图检测 striped 加密的 stripe size（块大小，默认探测 0x100）。
  4. 按 stripe 解密 `.text`/`.rodata`，解密后以指令有效性验证，失败则不修改数据。

### P8：metadata 字符串 XOR 解密

- 参考 `Core/String-Decryptor/Plugin.cs`，在 metadata 解析阶段检测：若字符串字典存在 key 缺失（null 终止符非 null），则以 null terminator 为 XOR key 逐个解密字符串并写回。

### P9：API export 名 ROT 解密

- 参考 `Core/API-Discovery/Plugin.cs`，在 ELF/PE 符号表枚举时对 export 名做 ROT1-25 尝试，匹配 `il2cpp_`/`_il2cpp_`/`__il2cpp_` 前缀后登记到 `api_export_rvas`。

### P10：原神 0x10 字节块 XOR + miHoYo 判定法

- 参考 `Loaders/miHoYo/Plugin.cs`（仅独立部分）：
  - miHoYo metadata 判定：文件头 magic 非 MetadataSignature 且末尾 0x4008 处 DWORD 指向自身。
  - 原神 XOR：固定 key `{0xAD,0x2F,0x42,0x30,0x67,0x04,0xB0,0x9C,0x9D,0x2A,0xC0,0xBA,0x0E,0xBF,0xA5,0x68}`，`step=(len>>14)<<6`，每 step 字节对 0x10 字节做 XOR。
- DLL 调用部分（`DecryptMetadata`/`GetStringFromIndex`/`GetStringLiteralFromIndex`）不移植（依赖 Windows UnityPlayer.dll）。

### P11：鬼谷八荒减法解密

- 参考 `Loaders/guigubahuang/Plugin.cs`：从位置 21 起用 ASCII key 循环减法（`bytes[pos] -= key[i % len]`）；验证位置 21 处 4 字节减 key 后等于 metadata magic。预设 key 表（0.8.1010/0.8.1012）+ 用户自定义 key 双模式。

### P12：字符串字面量 ROT 解密

- 参考 `Examples/StringLiterals-ROT/Example.cs`，在 stringliteral 输出阶段做 ROT 尝试（示例性质，可选）。

---

## 6. 许可合规

| 项目 | 许可 | 对移植的影响 |
|---|---|---|
| il2cpp-dumper-rs | MIT | 主引擎，无限制 |
| Cpp2IL | MIT | 可直接参考、逐行移植（P2/P3/P5/P6 等） |
| Il2CppInspectorRedux | **AGPL v3** | 移植代码会产生 AGPL 派生代码，App 整体开源义务不明；**建议仅参考结构与算法差异、自行编码实现（P1/P4），不直接复制代码**。若必须复制，需法务确认 |
| Il2CppInspectorPlugins | **AGPL v3** | 与 Redux 相同：**参考实现**（P7–P12 按算法描述自行编码）。用户已确认该仓库「完全开源即可补充」，本方案按算法移植 + 注明出处处理 |

> 说明：AGPL v3 是完全开源许可证（允许自由使用、修改、分发，但衍生作品须以 AGPL 开源）。本项目 App 侧为开源项目，若采纳 AGPL 派生代码，需确保整体以兼容方式开源。

---

## 7. 实施计划

> 状态（2026-08-21）：**仓库已拆分**。引擎仓 `il2cpp-dumper-rs/` 独立管理源码与预编译 .so；App 仓 `app/` 依赖预编译 .so，不再内置 Rust 编译任务。

| 阶段 | 内容 | 状态 |
|---|---|---|
| 阶段 1 | `dump_engine.rs` 库化 + `jni_bridge.rs` + Cargo.toml（cdylib） | 已完成 |
| 阶段 2 | P1/P2：metadata v106.1/107/108/110 + Mfuscator 解密（P3） | 已完成 |
| 阶段 3 | P7–P12：插件算法解密管线（二进制 XOR / 字符串 XOR / ROT / 原神 / 鬼谷八荒） | 待实施 |
| 阶段 4 | P4：ARM64 定位增强 | 待实施 |
| 阶段 5 | P5 评估与拆分（IL 恢复的可行性验证） | 远期 |
| 仓库拆分 | 引擎仓 `il2cpp-dumper-rs/` + App 仓 `app/` 双仓独立 | **已完成** |

## 8. 风险与注意事项

- **AGPL 传染**：Il2CppInspectorRedux 与 Il2CppInspectorPlugins 均为 AGPL v3，代码不能直接进 MIT 主引擎，P1/P4/P7–P12 必须「参考实现」。调研已把算法描述为结构级说明，足够支撑自行编码。用户已确认插件仓库可纳入，需在最终开源声明中注明算法出处。
- **P7（二进制 XOR 解密）的误判风险**：启发式依赖 .rodata 字节频率与 ARM 指令特征，对非 ARM 或特殊编译选项的二进制可能误判；移植时保留「解密后验证（指令有效性直方图）」再落盘，失败则不修改数据。
- **v108 是最大改动点**：9 个新 section + 字段大迁移 + 动态索引宽度，涉及 metadata 与二进制两侧结构，移植时需对照 `Metadata.cs` 213–239 行与 `Il2CppGlobalMetadataHeader.cs` 的 v108 分支逐字段核对。
- **v107 假升级**：Unity 6000.5 的「假 107」会误导解析，必须保留回退检测，否则新版本游戏直接解析失败。
- **IL 恢复工程量极大**（30+ 分析 pass、SSA、4 套指令集），不建议在 Android 端首发，P5 按远期拆分。
- **dll_il_recovery 的产出消费**：含真实 IL 的 DLL 需要反编译器配合，Android App 内无法直接使用，二期以 PC 工具或中间格式落地更合理。
- **miHoYo 插件的 DLL 依赖部分不移植**：`DecryptMetadata` 等需 Windows 版 UnityPlayer.dll 动态调用，Android 无此环境；原神 XOR 与判定法独立可移植（P10），但需要对应游戏版本的固定 key 才有效。
- **鬼谷八荒 key 表时效性**：预设 key 仅覆盖 0.8.1010/0.8.1012 两版，新版本需用户提供 key；移植为「预设表 + 用户自定义 key」双模式。
- **Cpp2IL 有私有 nuget 源**（`nuget.samboy.dev`）与 `development` 分支依赖，参考代码时以仓库内源码为准，不引入其构建链。

---

## 9. 参考文件索引（C# 侧关键路径）

- Il2CppInspectorRedux（/workspace/third_party/Il2CppInspectorRedux）：`Il2CppInspector.Common/Next/MetadataVersions.cs`、`Next/Metadata/Il2CppGlobalMetadataHeader.cs`、`IL2CPP/Metadata.cs`、`Architectures/Il2CppBinaryARM64.cs`、`Next/BinaryMetadata/Il2CppMetadataRegistration.cs`、`Il2CppInspector.Redux.CLI/Commands/ProcessCommand.cs`
- Cpp2IL（/workspace/third_party/Cpp2IL）：`LibCpp2IL/Metadata/Il2CppMetadata.cs`、`LibCpp2IL/LibCpp2IlMain.cs`、`Cpp2IL.Core/OutputFormats/AsmResolverDllOutputFormatIlRecovery.cs`、`Cpp2IL.Core/IlGenerator.cs`、`Cpp2IL.Core/Model/Contexts/MethodAnalysisContext.cs`、`Cpp2IL.Plugin.Mfuscator/MfuscatorSupportPlugin.cs`
- Il2CppInspectorPlugins（/workspace/third_party/Il2CppInspectorPlugins）：`Core/XOR-Decryptor/Plugin.cs`、`Core/String-Decryptor/Plugin.cs`、`Core/API-Discovery/Plugin.cs`、`Core/Binary-Metadata-Field-Reconstructor/Plugin.cs`、`Loaders/miHoYo/Plugin.cs`、`Loaders/miHoYo/MappedTypes.cs`、`Loaders/guigubahuang/Plugin.cs`、`Examples/StringLiterals-ROT/Example.cs`
