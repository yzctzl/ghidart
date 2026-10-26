# 本地 ARM64 样例

每组都包含原始二进制和完整 `b4a.json`，不依赖 b4a 的其他输出文件。
[manifest.json](manifest.json) 记录目标、Dart 版本、Code 数量、文件长度及 SHA-256。
这些是用户提供的真实应用材料，未核实再分发许可；本地迁移可携带，不要公开提交。

| 目录 | 二进制 | 用途 |
| --- | --- | --- |
| `android-arm64/` | `libapp.so`，ELF | Dart 3.10.8、压缩指针、完整静态分析 |
| `ios-arm64/` | `App`，Mach-O | Dart 2.19.6、非压缩指针 |
| `macos-arm64/` | `App`，FAT Mach-O | Dart 3.11.5、ARM64 slice 与容器身份验证 |

在 ghidart 根目录运行 `./gradlew verifySamples`，需先设置 `GHIDRA_INSTALL_DIR`
和 `JAVA_HOME`。命令复用导入器的读取和哈希逻辑，不加载 Ghidra 程序。
可用 `-PsamplesDir=/path/to/samples` 校验迁移后的同类样例目录。

GUI 检查：

1. 导入一组中的 `libapp.so` 或 `App`；macOS FAT 文件选择 **ARM64**，不要选 x64。
2. 测试旧 Dart 语言时选择 `AARCH64:LE:64:dart` / `dart`，暂不以其反编译质量验收。
3. 运行 `ImportB4a.java`，选择同目录的 `b4a.json`，再选择刚才导入的原始二进制。
4. 检查 `b4a` 类别的书签和 `b4a_entry_<rva>` 标签。入口应为 image base + RVA；
   已有非默认名称不应被覆盖。不应自动建立函数体或导入 IL/类型。
5. 在测试数据库中将二进制与其他组 JSON 混用，应拒绝导入且不写入部分结果。

不要将 FAT 容器的 SHA-256 和 `image.sha256` 直接比较：后者是 ARM64 slice 哈希。
清单另外记录整个文件哈希，便于传输后检查。两份 JSON 的 IL 文本也不适合逐字比较，
其中部分描述含进程相关显示值。

只迁移源码时可省略三个样例目录；要继续复现实验，请保留它们。样例未裁剪、未压缩，
`b4a.json` 包含当前已有的所有导出段，方便后续类型/语义工作直接使用。
