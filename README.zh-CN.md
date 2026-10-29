# ghidart

[English](README.md) | 简体中文

Dart AOT 的 Ghidra 扩展，目前支持 ARM64。
复用 Ghidra 官方 ARM64 解码器和反编译器，保留原始指令和寄存器存储。

提供：

- Dart managed ABI：X15 栈、CPU/FPU/栈参数、返回值和寄存器保存规则。
- 独立的机器码函数发现、控制流分析和调用链参数/返回值恢复。
- 已验证 SDK 的 RuntimeEntry、写屏障、栈检查及 Mint helper 契约。
- 可选读取配套 `b4a.json`，校验二进制身份和映射后导入代码边界及多入口标签。

**仍是实验项目，正确性与稳定性尚未经过全面验证。** 未知间接跳转、SDK 或调用约定保留为未知。
通用 native/FFI、动态栈上的活跃 Runtime 返回值和实机调试尚未完整支持或验收。
b4a 的类、名称、对象池和高级分析数据尚未完整导入。

## 安装

需要 Ghidra 12.2 PUBLIC、Java 25；项目自带 Gradle Wrapper。

```sh
export JAVA_HOME=/path/to/jdk-25
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew --no-daemon buildExtension
```

在 Ghidra 的 **File → Install Extensions** 中安装 `dist/` 下的 ZIP，然后重启。
也可执行 `./gradlew --no-daemon installExtension`，安装到上述 Ghidra 目录。
更新已打开的 Ghidra 时仍需重启。

## 使用

1. ELF 导入选择 **Dart AOT ELF**。Mach-O 使用官方加载器，选择语言
   `AARCH64:LE:64:dart`、编译器 `dart`；FAT 文件选择 ARM64 slice。
2. 有配套 `b4a.json` 时，放在二进制旁；也可通过
   **Dart AOT Code Boundaries → b4a.json path** 指定。身份或映射不符会拒绝导入。
3. 没有边界数据时，选择 Dart managed 代码区域，执行一次
   **Dart Machine Code Functions**。可通过 **Confirmed entry addresses** 补充入口。
4. 对需要分析的函数及相关被调用者执行 **Dart ABI**，然后打开反编译窗口。

机器码发现和 ABI 分析默认关闭，避免扫描混合的 native 代码或在导入时全量反编译。
不完整控制流标记为 `Dart: incomplete CFG`；用户修改的范围、签名和调用点原型会被保护。
ghidart 的消息显示在 Ghidra Console 中。Dart 语言使用 `VMSP`、`THR` 等寄存器名；
物理名 `x15`、`x26` 等仍是同一寄存器的别名，供调试使用。

精确 SDK helper 配置目前验证了 Android 3.10.8、iOS 2.19.6、macOS 3.11.5。
其他版本仍可使用通用 managed ABI；特殊契约仅在身份、布局及指令证据匹配时应用。

## 文件与校验

源码位于 `src/main/java/ghidart/`，语言定义位于 `data/languages/`。
官方解码器由构建复制，无需维护另一份 ARM64 指令集。
b4a 数据格式见 [B4A_INTERFACE.md](B4A_INTERFACE.md)。

原有轻量验证器位于 `tests/`；本地应用样例和大型实测材料不进入发布包。
准备好二进制与 `b4a.json` 样例后，可运行离线身份校验：

```sh
./gradlew --no-daemon verifySamples -PsamplesDir=/path/to/samples
```

样例目录结构见 [samples/README.md](samples/README.md)。校验通过不代表已执行 Ghidra 分析。
许可与模板来源见 [LICENSE](LICENSE)。

文档默认使用英文。修改本 README 或 [README.md](README.md) 时，必须同步更新另一版本。
接口、样例和测试说明仅维护英文。
