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
- 可选 b4a 集成（L3）：从统一 `b4a.json` 导入边界、分层类/函数名、原始字段布局、
  Thread/池槽位、操作数引用和已识别 IL 注释。

**仍是实验项目，正确性与稳定性尚未经过全面验证。** 未知间接跳转、SDK 或调用约定保留为未知。
通用 native/FFI、动态栈上的活跃 Runtime 返回值和实机调试尚未完整支持或验收。
b4a 打印的类型和 IL 作为导出证据显示，不直接转换为物理 ABI 或替换 P-code。

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
   - 快照格式受支持、没有 b4a 数据：在 Auto Analyze 中保持 **Dart AOT Objects**（L2）开启，
     或通过 One Shot 执行，创建函数、
     入口标签、字符串、对象关系和按池区分的数据。
   - 有匹配的 `b4a.json`：二进制旁存在配套 JSON 时，默认启用 **Dart b4a Import**（L3）。
     仍可关闭、通过 One Shot 手动执行，或在分析选项中指定 **b4a.json path**。它同时创建边界；
     **Dart AOT Code Boundaries** 仍可用于只导入边界。
   - 快照不可读或经过自定义修改：选中 managed 可执行区域，执行
     **Dart Machine Code Functions**（L1）；必要时通过 **Confirmed entry addresses** 补充入口。
3. 选中关注的函数，执行 **Dart ABI**，然后打开反编译窗口。
   L2 或 b4a 提供边界后，仍需执行 ABI 恢复。
4. ABI 恢复后，可选执行 **Dart Value Uses**。

Dart 语言下，这六项均可通过 **Analysis → One Shot** 执行。
L2 和 b4a 导入始终读取完整输入，不受选区限制；选区用于限定机器码发现范围
和 ABI／值分析的起始函数集合。L2 无法解析新输入时，可在独立确认边界的指令图像内
自动执行 L1 函数发现；没有可靠边界时，需要手动选择托管代码范围。
拒绝解析时保留已有 L2 数据；b4a 导入和 ABI 分析仍需显式执行。
语言 **upgrade** 只更新数据库的语言模型，
不会重新分析，也不会修改数据库中保存的分析选项。

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
和常量用途保存到数据库。通过 **Dart → Show Value Uses** 可在 Console 查询。
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
在已定义的字符数据或引用它的指令上选择 **Dart → Show Characters**，可在控制台查看
完整内容、地址、字节长度和转义码元。该视图保留 NUL 和孤立代理码元，不改变反编译语义。
对支持的快照，可在 **Dart ABI** 前执行 **Dart AOT Objects**。
这个 L2 分析器独立读取映射中的快照符号，不依赖 b4a；创建函数边界及多入口标签，
将字符串原始字符区定义到 **Defined Strings**，并在 `OTHER` 地址空间内不加载的 `DartObjects_*` 数据区中
保存对象关系和池条目。通过 **Symbol Tree → Namespaces/Classes → Dart** 查看按库 URL、类、函数组织的层级。
顶层函数位于库作用域，归属已知的分配/字段 stub 位于相应类中。
共享机器码在各所属作用域中保留声明标签，共用一个函数体。
**Dart → ObjectPools → isolate → pool_<id> → slots** 可打开 Listing 中的逻辑池；
各槽位注释显示 PP 偏移、类型、初始值和可修改标志。
已确认的 PP 访问会引用池槽，直接加载字符串时也引用字符数据，
可从 **Defined Strings → References** 返回代码。引用表示快照初始值，
不保证运行时修改后仍为常量。仅用于元数据的字符串通过对象引用导航。
序列化的字符串长度/编码前缀与正文分别定义，这些字节不是字符串尾部的乱码。
这些逻辑身份不是运行时堆地址。声明关系、类型、逻辑签名和
已解码的整数保存在数据库属性中；逻辑参数数量不会替代机器码 ABI 推断。
同时保留序列化对象字段与字节区间。已适配的根表布局还将命名根引用、字段值／偏移引用和静态字段表
保存为可导航的槽位。静态字段（包括共享字段）链接到快照中的初始值，
不代表运行后修改的值；Type 和实例链接到所属类。Code 对象和已解析的 dispatch 条目链接到指令入口；
延迟加载目标在对应加载单元可用前保持未解析。即使没有本地函数体，也保留 Function 声明到 Code 的关系；
`LazyCompile` 标为辅助入口，不误标为已编译业务函数。逻辑对象和池槽显示整数及 Double 值，
Double 同时保留精确位模式。
固定大小的用户类布局位于 **Data Type Manager → Dart → L2**。字段位置从目标字单位
转换成字节偏移；tagged 槽位不冒充 native 指针，未知的 unboxed 数字类型保留为原始存储。
继承字段沿已保留的父类关系命名。SDK 定义的 null、布尔值和 sentinel 等基础对象
及内部 Class 对象位于 **Dart → VM → BaseObjects**。
VM 缓存对象保留独立编号标签，不猜测文件中没有的运行时内容。

打开延迟单元 `*-<id>.part.so`／`.dylib` 时，将根文件及祖先单元放在旁边。
L2 临时读取父引用表，验证程序身份后应用该单元的 Code／池补丁；其他文件名可通过
**Parent AOT file** 指定直接父二进制。缺少父文件或身份不符时拒绝 L2，不编造地址。
ABI 恢复后，**Dart Value Uses** 可为明确对应的池加载局部变量命名，保留原推断类型及用户修改。
名称可带出已知的初始字符串／基础对象提示，不将可变的快照初始值折叠为常量。
还会沿 SSA 搬移和无歧义合并追踪类分配结果、不可 patch 的池实例；明确的字段访问
链接到保留的 Field 声明，包括继承字段，生成的局部变量带出类名／字段名。
整个 SSA 局部变量能证明持有同一 Class 的完整 tagged 指针时，使用 Ghidra 原生的
偏移指针类型显示 `ADJ(obj)->field`；压缩值仍保留为整数。
**Dart → Show Value Uses** 可查看对象、实参和返回值的来源。
未知调用、歧义值或缺失声明会停止传播，不将逻辑签名替换为物理 ABI。
hash 只提供候选读取器：匹配失败后回退到完整结构解码，互相矛盾的解读会被拒绝。
完整版本覆盖仍在实现中。仅凭池偏移仍不能确定代码访问点对应哪个对象或字符串。

新导入的 Dart 程序默认开启 L2。未知格式、未适配的根表或非法 cluster 数据会被拒绝，L1 保持独立。
成功执行时，控制台会报告函数名、字符串、池槽位数量及 `Root stream fully consumed`；
`L2 rejected` 表示没有发布任何 L2 数据。
相同输入可以重复执行；已发布快照的字节或映射发生变化时，会保留旧数据并拒绝替换，
二进制变化或旧版已发布数据的代次不兼容时，应重新导入项目。格式配置仅覆盖选定的 SDK 布局，
不代表 2.10 至 3.13 的每个版本都已经支持。

为支持的栈检查和写屏障调用点建立局部契约；直接 shared helper 还需要验证保存、恢复和结果槽。
无法确定目标地址的间接调用保留原样。L2/L3 元数据可提供更强的信息。

## b4a 集成（L3）

对配套的 ARM64 ELF 或 Mach-O 执行 **Analysis → One Shot → Dart b4a Import**。
二进制旁存在配套 JSON 时默认启用；已保存的分析选项优先，仍可手动通过 One Shot 执行。
原始文件身份和加载后的 RVA 校验必须一致。
导入使用事务，取消或失败时回滚；相同文档重复执行会跳过。不同文档需要新数据库，
避免静默替换已有用户修改。
大导出文件可能需要数分钟及磁盘临时空间；较小的内存 `/tmp` 可能耗尽。
需要时在启动 Ghidra 前设置 Java 参数 `-Djava.io.tmpdir=/path/on/disk`。

通过 **Symbol Tree → B4a → Libraries** 查看库、类和声明层级，
通过 **B4a → Structures** 查看导出的 Thread/ObjectPool 槽位，
通过 **Data Type Manager → Dart → B4a** 查看布局。物理函数保持单一所有者；
共享代码的多个声明分别保留并建立链接。用户名称、注释、签名、类型和操作数引用受到保护。
已识别 IL 和注释放在对应指令旁；完整记录（参数、签名、标志、未知 IL 等）保存在数据库属性中，
在函数或槽位处选择 **Dart → Show b4a Records** 可以查看。

若没有 Dart 菜单，在 **File → Configure** 中启用 **DartViewsPlugin**。
三个原生动作替代旧脚本，不再需要配置 Script Manager。

导出的池描述作为不透明文本保留，不将正文中的地址当作指针，不猜字符串位置，
也不折叠可变池值。已解析的操作数引用指向 `B4aMetadata`（`OTHER`）中的导出逻辑槽位，
不是运行时堆地址。L2 能解析快照时仍独立提供真实字符串数据和对象关系。
逻辑 Dart 类型/签名不替代机器 ABI，反编译前仍照常执行 **Dart ABI**。

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

源码按职责组织在 `src/main/java/ghidart/` 下：

- `analysis/`：函数发现、ABI、值／对象使用分析及 P-code 注入。
- `snapshot/`：L2 格式配置、解码、对象、类型与数据库发布。
- `importer/`：ELF 装载、b4a 校验与语义导入。
- `datatype/`：显式长度的字符数据类型。
- `listing/`：原生 Console 动作及兼容已保存布局的操作数字段。

共享日志位于 `analysis/`；迁移的字符和操作数字段类通过 Ghidra 原生类名映射兼容已有数据库和布局。

语言定义位于 `data/languages/`。
构建通过 Ghidra 模块宏引用已安装的官方 ARM64 源码。小型 SLEIGH 包装仅规范化等价的
有符号字运算，保留指令编码和寄存器存储，无需维护另一份指令集。
b4a 数据格式见 [B4A_INTERFACE.md](B4A_INTERFACE.md)。

样例和验证工具仅保留在本地，不进入 Git 或扩展包。本地存在 `tests/VerifyB4a.java` 时，
可运行 `./gradlew --no-daemon verifySamples -PsamplesDir=/path/to/samples` 校验
二进制与 JSON 身份；这不代表已执行 Ghidra 分析。许可与模板来源见 [LICENSE](LICENSE)。

文档默认使用英文。修改本 README 或 [README.md](README.md) 时，必须同步更新另一版本。
接口、样例和测试说明仅维护英文。
