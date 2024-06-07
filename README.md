# ghidart

Dart ARM64 Ghidra 扩展的源码归档，恢复自 2024 年备份。
保留原始 Java 实现、帮助资源、SLEIGH 语言和编译器规格。
本提交作为历史基线，不包含后续的现代构建脚手架和分析器改进。

旧 ABI 的返回地址、参数和调用破坏规则尚需校正，函数发现逻辑尚未验收。
此归档不代表完整可用的 Dart 反编译支持。

## 目录

- `src/main/java/ghidart/`：原始 Loader、Analyzer、Plugin、Exporter、FileSystem。
- `src/main/help/`：原始帮助资源。
- `data/languages/`：ARM64 指令语义、寄存器和编译器规格。
- `data/patterns/`：旧 ARM64 通用函数模式，不能直接作为 Dart 边界依据。

源码不得当作构建缓存清理。保留 [Apache 2.0 许可](LICENSE) 和原始文件头。
