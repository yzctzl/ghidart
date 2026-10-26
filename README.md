# ghidart

Dart AOT 的 Ghidra 实验扩展，当前提交建立 ARM64 处理器基础。
使用构建所选 Ghidra 安装中的官方 AARCH64 解码器，不维护另一份指令集。
物理寄存器名保持不变，以 alias 表达 Dart 角色。

## 构建

环境：Ghidra 12.2 PUBLIC、Java 25、Gradle 9.1.0。

```sh
export JAVA_HOME=/path/to/jdk-25
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew --no-daemon buildExtension verifySamples
```

Windows 使用 `gradlew.bat`。在 Ghidra 中安装 `dist/` 的扩展并重启。
使用官方 ELF/Mach-O Loader，手动选择 `AARCH64:LE:64:dart`、编译器 `dart`。
`tools/VerifyDartLanguage.java` 检查语言加载、物理寄存器及 Dart 别名。

当前只是处理器基础，旧 ABI 仍待第二阶段校正，不能视作完整反编译支持。
包括旧 `returnaddress=x0` 等问题将在 ABI 阶段修正；本提交不声明调用约定正确。
独立 AOT 识别、函数发现和动态调试尚未实现。
b4a 导入原型保留在 `ghidra_scripts/b4a/`，暂不随扩展打包。

旧通用 SLEIGH、函数模式和构建材料不再放在源码树中；原始内容保留在初始归档提交 `f3d5172`。
恢复的模板源码保留，但不编译、不发布；旧 Analyzer/Loader demo 不进入运行 JAR。
源码不得当作缓存清理。迁移时另行携带 Git 忽略的 `samples/`。

接口见 [B4A_INTERFACE.md](B4A_INTERFACE.md)，本地样例见 [samples/README.md](samples/README.md)。
保留 [Apache 2.0 许可](LICENSE) 与 Ghidra 原始文件头。
