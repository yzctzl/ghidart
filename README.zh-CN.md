# ghidart

[English](README.md) | 简体中文

Dart AOT 的 Ghidra 扩展，目前支持 ARM64。
复用 Ghidra 官方 ARM64 源码和反编译器，保留原始指令和寄存器存储。

提供：

- Dart managed ABI：X15 栈、CPU/FPU/栈参数、返回值和寄存器保存规则。
- 独立的机器码函数发现、控制流分析和调用链参数/返回值恢复。
- 依据支持的机器码模式恢复 RuntimeEntry、写屏障、栈检查及 Mint helper 契约。
- 使用标准符号扩展运算，更清晰地表达压缩 Smi 提取。
- 可选根据机器码中的内存使用推导参数访问布局，不依赖快照布局。
- 索引 PP 相对访问和常量用途，为已证明的具体地址和调用建立引用。
- 复用原生 switch／SSA 分析，经过完整 CFG 校验后恢复有限间接跳转。
- 可选原生堆基址表达式命名及明确长度的字符数据类型。
- 可选解析 AOT 快照，恢复函数入口、明确长度的字符串和按池区分的对象池数据（L2）。
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
   `AARCH64:LE:64:dart`、编译器 `dart`（若是 2.13 时代独立 x23 堆基址的二进制，则选择 `dart-r23`）；FAT 文件选择 ARM64 slice。
2. 先选择一种函数边界来源：
   - 快照格式受支持、没有 b4a 数据：执行 **Dart AOT Objects**（L2），创建函数、
     入口标签、字符串、对象关系和按池区分的数据。
   - 有匹配的 `b4a.json`：执行 **Dart AOT Code Boundaries**，或在 Auto Analyze 中
     保持该项开启。JSON 放在二进制旁，也可指定路径。目前只导入边界和入口标签，
     尚未导入全部 b4a 语义。
   - 快照不可读或经过自定义修改：选中 managed 可执行区域，执行
     **Dart Machine Code Functions**（L1）；必要时通过 **Confirmed entry addresses** 补充入口。
3. 选中关注的函数，执行 **Dart ABI**，然后打开反编译窗口。
   L2 或 b4a 提供边界后，仍需执行 ABI 恢复。
4. ABI 恢复后，可选执行 **Dart Value Uses**。

Dart 语言下，这五项均可通过 **Analysis → One Shot** 执行。
L2 和 b4a 边界导入始终读取完整输入，不受选区限制；选区用于限定机器码发现范围
和 ABI／值分析的起始函数集合。目前 L1／L2／b4a 尚未形成自动回退链，
需要先选择边界来源，再运行 ABI 分析。语言 **upgrade** 只更新数据库的语言模型，
不会开启 L2，也不代表已经执行了这些分析步骤。

机器码发现和 ABI 分析默认关闭，避免扫描混合的 native 代码或在导入时全量反编译。
不完整控制流标记为 `Dart: incomplete CFG`；用户修改的范围、签名和调用点原型会被保护。
ghidart 的消息显示在 Ghidra Console 中。Dart 语言使用 `VMSP`、`THR` 等寄存器名；
物理名 `x15`、`x26` 等仍是同一寄存器的别名，供调试使用。

L1 ABI 分析依据机器码，不依赖快照 hash 或 Thread 布局配置。
**Dart ABI → Infer observed memory shapes** 可进一步把参数相对地址访问显示为偏移成员。
该选项默认关闭，需要已恢复的物理原型；混合数值运算或逃逸的参数不会推导。
这些类型只描述实际观察到的访问，不是 Dart 类或完整对象。重分析会撤销未修改的自动类型；
编辑过的布局会作为用户原型保留。

ABI 恢复后，可选对选中函数运行 **Dart Value Uses**。它逐个反编译选中函数，全库运行
可能耗时较长。任务进度显示当前函数、阶段和完成数量；单函数反编译超时默认 20 秒，
可在选项中调整，结束汇总包含失败和超时数量。该分析将 PP 来源、字节偏移、访问宽度
和常量用途保存到数据库。运行 `ShowDartValueUses.java` 可在 Console 查询。
具体地址引用使用 Ghidra 原生导航；PP 偏移本身不代表池条目或字符串。
修改代码或签名后需要重新分析。该分析默认关闭。

**Dart Value Uses → Name heap-base expressions** 可将精确的 `HBS << 32`
中间值命名为 `heap_base`，保留可见的真实运算，不改变指令、寄存器或调用契约。
重分析会删除未修改的自动名称，保留用户修改。该选项默认关闭。

独立确定字符数据的地址、字节长度与编码后，可通过 Data Type Manager 对该范围应用
内置类型 `dart_chars8`（Latin-1）或 `dart_chars16le`（UTF-16LE）。数据库和 Listing
保留 NUL 及 UTF-16 码元；原始 UTF-16 码元通过 Bytes 编辑。这些类型不发现 Dart
对象，也不猜测长度或编码。原生反编译器内联字符指针时仍遵循 C 字符串规则，
不能完整内联包含中间 NUL 的内容。
在已定义的字符数据或引用它的指令上运行 **ShowDartCharacters.java**，可在控制台查看
完整内容、地址、字节长度和转义码元。该视图保留 NUL 和孤立代理码元，不改变反编译语义。
对支持的快照，可在 **Dart ABI** 前执行 **Dart AOT Objects**。
这个 L2 分析器独立读取映射中的快照符号，不依赖 b4a；创建函数边界及多入口标签，
将字符串原始字符区定义到 **Defined Strings**，并在 `OTHER` 地址空间内不加载的 `DartObjects_*` 数据区中
保存对象关系和池条目。通过 **Symbol Tree → Namespaces/Classes → Dart** 查看按库 URL、类、函数组织的层级。
顶层函数位于库作用域，归属已知的分配/字段 stub 位于相应类中。
共享机器码在各所属作用域中保留声明标签，共用一个函数体。
**Dart → ObjectPools → isolate → pool_<id> → slots** 可打开 Listing 中的逻辑池；
各槽位注释显示 PP 偏移、类型、初始值和可修改标志。
槽位可以引用对应的逻辑对象和字符串正文。这里表示快照初始值，
不保证运行时修改后仍为常量。可通过对象和池槽引用导航字符串。
机器码 PP 访问与对象的关联仍在完善中。
序列化的字符串长度/编码前缀与正文分别定义，这些字节不是字符串尾部的乱码。
这些逻辑身份不是运行时堆地址。声明关系、类型、逻辑签名和
已解码的整数保存在数据库属性中；逻辑参数数量不会替代机器码 ABI 推断。
同时保留序列化对象字段与字节区间。已适配的根表布局还将命名根引用、静态字段和 dispatch Code 索引
保存为可导航的数据库槽位。完整版本覆盖和不依赖 hash 的格式识别仍在实现中。
仅凭池偏移仍不能确定机器码访问点对应哪个对象或字符串。

L2 默认关闭。未知格式、未适配的根表或非法 cluster 数据会被拒绝，L1 保持独立。
成功执行时，控制台会报告函数名、字符串、池槽位数量及 `Root stream fully consumed`；
`L2 rejected` 表示没有发布任何 L2 数据。
相同输入可以重复执行；已发布快照的字节或映射发生变化时，会保留旧数据并拒绝替换，
应为变化后的二进制重新导入项目。格式配置仅覆盖选定的 SDK 布局，
不代表 2.10 至 3.13 的每个版本都已经支持。

为支持的栈检查和写屏障调用点建立局部契约；直接 shared helper 还需要验证保存、恢复和结果槽。
无法确定目标地址的间接调用保留原样。L2/L3 元数据可提供更强的信息。

## 兼容性

L1 的目标范围是 ARM64 Dart 2.10 至当前稳定版（3.13.7）。
SDK 源码检查覆盖 30 个发布标签；真实二进制验证覆盖部分版本，
尚未逐一验证所有版本和 OS 组合。2.10 之前的版本暂不纳入支持范围。

通用模型根据机器码证据处理栈参数与寄存器参数、新旧写屏障掩码、
单个与成对 Q 寄存器保存，以及新旧 Mint 分配路径。
对于 2.13 时代独立使用 x23 堆基址的 ABI，需要显式选择 `dart-r23`；
该配置从通用编译器规范生成，不依赖快照 hash。

本次修正了无条件 `b.al` 的解码。打开已有数据库时接受 Ghidra 的语言升级，
然后按需重新执行函数发现和 ABI 分析。用户修改过的函数仍受保护。

## 文件与校验

源码位于 `src/main/java/ghidart/`，语言定义位于 `data/languages/`。
构建通过 Ghidra 模块宏引用已安装的官方 ARM64 源码。小型 SLEIGH 包装仅规范化等价的
有符号字运算，保留指令编码和寄存器存储，无需维护另一份指令集。
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
