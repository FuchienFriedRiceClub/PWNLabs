# 格式化字符串的介绍

## 可变参数

在常规情况下，C语言中函数接收的形参数量都是固定的，但事实上，C语言中函数接受形参的数量并不是必须固定的，也支持动态变化的形参数量。

函数间传递可变参数时，基本的要求是函数至少指定一个参数。

C语言中可变形参的定义方式如下所示，除了首个参数指定类型和变量名外，后续的参数都通过`...`省略号代替。

```
(type arg1, ...)
```

除了`...`省略号代表动态变化的参数外，C语言还允许宏内通过`__VA_ARGS__`代替`...`。

```
__VA_ARGS__

示例：
#define test(...) orig(__VA_ARGS__)
```

### 可变参数的处理

首先先来看一下可变参数是如何传递的。下方给出了函数原型和函数调用。

```
void test(int num, ...)
test(10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0);
```

从反汇编上看，调用者保存寄存器处理了前6个参数，栈空间处理了后5个参数。此时可以知道，可变参数的传递也是遵循函数调用规范的。

```
push   $0x0
push   $0x9
push   $0x8
push   $0x7
push   $0x6
mov    $0x5,%r9d
mov    $0x4,%r8d
mov    $0x3,%ecx
mov    $0x2,%edx
mov    $0x1,%esi
mov    $0xa,%edi
call   test
```

对于可变参数的处理，GLibC提供了下方的4个接口函数。

```
void va_start(va_list ap, last);
type va_arg(va_list ap, type);
void va_end(va_list ap);
```

#### va_list

这几个接口函数都会接收一个类型为`va_list`的变量，`va_list`的全称是可变参数列表`variable argument list`。

```
typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;
```

追踪`va_list`的定义时一开始会查找`usr`目录下的`stdarg.h`，但是这个头文件到`__builtin_va_list`就结束了，头文件中没有又在编译过程中产生，难道是GCC内部定义的？

在GCC的文档中，有一个特殊的专栏`gccint`，这个专栏主要是介绍GCC编译器的内部结构，其中`18.10 Implementing the Varargs Macros`专门介绍了`vaargs`相关宏的实现。

```
https://gcc.gnu.org/onlinedocs/gccint/Varargs.html
```

通过浏览GCC源代码可以发现，`__builtin_va_list`并不是直接定义的，而是GCC内部生成的，并且`__builtin_va_list`的定义是区分体系结构的，下面展示了X86架构的情况。

```
ix86_build_builtin_va_list_64
	-> build_decl (BUILTINS_LOCATION, TYPE_DECL, get_identifier ("__va_list_tag"), record);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("gp_offset"), unsigned_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("fp_offset"), unsigned_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("overflow_arg_area"), ptr_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("reg_save_area"), ptr_type_node);
```

可以在GDB中打印`va_list`变量确认这一点。

```
p /x valist
$1 = {{gp_offset = 0x8, fp_offset = 0x30, overflow_arg_area = 0x7fffffffde90, reg_save_area = 0x7fffffffddd0}}
```

通过查看目前另外一种非常流行的体系结构ARM，可以看到`__builtin_va_list`的成员结构与X86几乎完全不同。

```
aarch64_build_builtin_va_list
	-> build_decl (BUILTINS_LOCATION, TYPE_DECL, get_identifier ("__va_list"), va_list_type);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__stack"), ptr_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__gr_top"), ptr_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__vr_top"), ptr_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__gr_offs"), integer_type_node);
	-> build_decl (BUILTINS_LOCATION, FIELD_DECL, get_identifier ("__vr_offs"), integer_type_node);

p /x valist
$3 = {__stack = 0x7ffffff1c0, __gr_top = 0x7ffffff1c0, __vr_top = 0x7ffffff180, __gr_offs = 0xffffffc8, __vr_offs = 0xffffff80}
```

GCC支持的目标体系结构有很多，为了统一管理不同体系结构的实现，GCC定义了`TARGET_`宏接口，不同体系结构的实现需要绑定到对应的接口上。

比方说针对`va_list`的实现都绑定到`TARGET_BUILD_BUILTIN_VA_LIST`宏上。

```
#define TARGET_BUILD_BUILTIN_VA_LIST aarch64_build_builtin_va_list
#define TARGET_BUILD_BUILTIN_VA_LIST ix86_build_builtin_va_list

ix86_build_builtin_va_list
	-> ix86_build_builtin_va_list_64
```

每种体系结构的实现文件中都必须指定`targetm`成员，且该成员必须绑定到`TARGET_INITIALIZER`宏上。

```
struct gcc_target targetm = TARGET_INITIALIZER;
```

该宏的作用是初始化目标端架构信息，在`target.def`文件中实现`gcc_target`。

但它定义`gcc_target`结构体比较特殊。

```
HOOK_VECTOR (TARGET_INITIALIZER, gcc_target)
......
HOOK_VECTOR_END (C90_EMPTY_HACK)
```

先来看一下`HOOK_VECTOR`宏，它其实就是定义`struct xxx {`。

```
#define HOOKSTRUCT(FRAGMENT) FRAGMENT
#define HOOK_VECTOR_1(NAME, FRAGMENT) HOOKSTRUCT (FRAGMENT)
HOOK_VECTOR(INIT_NAME, SNAME) HOOK_VECTOR_1 (INIT_NAME, struct SNAME {)
```

当我们看到单`{`的时候一定会感觉很奇怪，怎么缺了一半！为了实现结构体的定义，缺的部分就一定有东西补上，在这里补缺口的就是`HOOK_VECTOR_END`。

`HOOK_VECTOR_END`匹配`HOOK_VECTOR`一块定义了`struct {,} xxx;`。

```
#define HOOK_VECTOR_END(DECL_NAME) HOOK_VECTOR_1(,} DECL_NAME ;)
```

结构体中的成员定义会一般会通过`DEFHOOK`定义，该宏会定义根据返回值数据类型`TYPE`、函数名`NAME`、形参列表`PARAMS`定义出函数指针变量。

```
#define DEFHOOK(NAME, DOC, TYPE, PARAMS, INIT) TYPE (* NAME) PARAMS;
```

以下方的`DEFHOOK`为例，它定义了`tree build_builtin_va_list(void)`。

```
DEFHOOK (
	build_builtin_va_list,
	"...",
	tree, (void),
	std_build_builtin_va_list
)
```

除了`DEFHOOK`宏之外，也可以通过`DEFHOOKPOD`宏定义一个普通变量。

```
#define DEFHOOKPOD(NAME, DOC, TYPE, INIT) TYPE NAME;
```

从上面可以看到`HOOK_VECTOR`和`HOOK_VECTOR_END`打着`TARGET_INITIALIZER`的旗号于定义了`gcc_target`结构体。

至于`TARGET_INITIALIZER`宏的真身，则会在编译过程中展现。编译时会生成`target-hooks-def.h`，其中包含着`TARGET_INITIALIZER`宏的定义。

```
#define TARGET_INITIALIZER \
	{ \
		...... \
		TARGET_BUILD_BUILTIN_VA_LIST, \
		...... \
	}
```

GCC会通过`targetm`接口针对不同的架构定制生成的信息。比如下面通过`targetm.build_builtin_va_list`接口生成`va_list`。

```
c_common_nodes_and_builtins
	-> build_common_tree_nodes
		-> tree t = targetm.build_builtin_va_list ()
		-> va_list_type_node = t
	-> lang_hooks.decls.pushdecl(build_decl (UNKNOWN_LOCATION, TYPE_DECL, get_identifier ("__builtin_va_list"), va_list_type_node))
```

在`ix86_build_builtin_va_list`函数中我们会看到这样一种现象，就是获取`va_list`时会拿两次，分别对应`sysv`和`ms`，返回时会先判断，再选择其中的一种作为返回值。

这是因为GCC支持两种应用程序二进制接口`ABI Application Binary Interface`类型，一是`System V`，对应Unix/Linux平台，二是`MicroSoft`，对应微软的Windows平台，GCC会根据当前使用的平台进行选项。

Unix/Linux平台使用的ABI被称作是`ELF Executable and Linkable Format`，而Windows平台使用的ABI则被称作是`PE Portable Executable`，两种格式的ABI其实是非常接近的，因为它们都源自于`COFF Common File Format`。

```
ix86_build_builtin_va_list
	-> sysv_va_list_type_node
	-> ms_va_list_type_node
	-> return ((ix86_abi == MS_ABI) ? ms_va_list_type_node : sysv_va_list_type_node);
```

在X86架构中，`va_list`中存在`gp_offset`、`fp_offset`、`overflow_arg_area`、`reg_save_area`四个成员，其中`overflow_arg_area`指向非寄存器存储的数据地址（一般放在栈上），`reg_save_area`指向寄存器存储的数据地址（一般会从寄存器挪到栈上），`gp_offset`是指通用寄存器保存的数据在`reg_save_area`中的偏移值，`fp_offset`是指浮点寄存器保持的数据在`reg_save_area`中的偏移值。

```
----------------------------------------------
caller   | ...                               |
stack    | arg7, arg8, ..., argX             | <----|
----------------------------------------------      |
         | callee return                     |      |
         | caller rbp                        |      |
----------------------------------------------      |
         | ......                            |      |
		 | xmm0 - xmm7                       | <--| |
callee   | rdi, rsi, rdx, rcx, r8, r9        | <--| |
stack    | ......                            |    | |
         | fp_offset         | gp_offset     |    | |
         | overflow_arg_area | reg_save_area |    | |
------------------^------------------^--------    | |
                  |                  |            | |
				  |                  |------------| |
                  |---------------------------------|
```

这里还需针对浮点数据特殊说明一下，下面展示了一个带有浮点类型数据的调用。

```
void test(int num, ...)
test(20,
	1.1, 2.1, 3.1, 4, 5, 6, 7, 8.2, 9.11, 0.11,
	1.1, 2.1, 3.1, 4, 5, 6, 7, 8.2, 9.11, 0.11);
```

从上方可以看到，`test`函数接受了许多的浮点数据。

在当前CPU中浮点寄存器一共有8个，如果可变参数列表中的浮点数据未超出8个，那么就会将当前传递的浮点数据数量放入`rax`寄存器中，如果超出了就将上限8压入`rax`寄存器中。

```
存入10个浮点数据：
mov    $0x8,%eax
call   test

存入3个浮点数据：
mov    $0x3,%eax
call   test
```

对于超出浮点寄存器存储上限的部分，当然也是放到栈上。

针对浮点数的处理可以分成四个阶段，第一个阶段是给1到7号浮点寄存器赋值，并将0号浮点寄存器的数值先放到`rax`内（因为0号浮点寄存器后面会用）。

第二个阶段是处理超出存储容量的浮点数，它有着非常统一的格式`movsd val,%xmm0 ; lea -0x8(%rsp),%rsp ; movsd  %xmm0,(%rsp)`，第一步做的保存浮点数到寄存器`xmm0`，第二步是将`rsp`减去0x8再更新`rsp`，这相当于对栈进行扩容，第三步是将`xmm0`中保持的浮点数存放到刚扩大的栈上。

阶段三是还原`xmm0`寄存器中本应存放的数值。

阶段四是处理浮点寄存器保持的浮点数数量，然后调用函数。

```
阶段一：
movsd  0xdc1(%rip),%xmm7
movsd  0xdc1(%rip),%xmm6
movsd  0xdc1(%rip),%xmm5
movsd  0xdc1(%rip),%xmm4
movsd  0xdc1(%rip),%xmm3
movsd  0xdc1(%rip),%xmm2
movsd  0xd91(%rip),%xmm1
mov    0xd92(%rip),%rax

阶段二：
sub    $0x8,%rsp
movsd  0xd8e(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)
movsd  0xd84(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)
movsd  0xd7a(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)
movsd  0xd6a(%rip),%xmm0
lea    -0x8(%rsp),%rsp
movsd  %xmm0,(%rsp)

阶段三：
movq   %rax,%xmm0

阶段四：
mov    $0x8,%eax
call   test
```

进入接收可变参数的函数后，如果判断`rax`寄存器中的数值非零，就会将8个浮点寄存器上的数值存储到栈上。

```
test   %al,%al
je     1191 <va_args4int+0x58>
movaps %xmm0,-0x80(%rbp)
movaps %xmm1,-0x70(%rbp)
movaps %xmm2,-0x60(%rbp)
movaps %xmm3,-0x50(%rbp)
movaps %xmm4,-0x40(%rbp)
movaps %xmm5,-0x30(%rbp)
movaps %xmm6,-0x20(%rbp)
movaps %xmm7,-0x10(%rbp)
```

#### va_start

`va_start`的作用是初始化可变参数列表，它的原型是`__builtin_va_start`，也是GCC内部实现的，实现方式大同小异，这里就不再进行解析了。

```
gcc_target中的定义实现 - target.def：
DEFHOOK_UNDOC(
	expand_builtin_va_start,
	"Expand the @code{__builtin_va_start} builtin.",
	void, (tree valist, rtx nextarg), NULL
)

指定架构中的va_start实现：
#define TARGET_EXPAND_BUILTIN_VA_START ix86_va_start

针对架构生产的gcc_target信息（通过宏绑定成员）：
target-hooks-def.h
#define TARGET_INITIALIZER {
	......
	TARGET_EXPAND_BUILTIN_VA_START,
	......
}

GCC对需要展开函数的生成过程：
expand_builtin
	-> case BUILT_IN_VA_START
		-> expand_builtin_va_start
			-> targetm.expand_builtin_va_start
```

`va_start`的实现在程序编译时会被GCC编译器直接放进去，下方展示的是`va_start`对应的汇编代码。

```
movl   $0x8,-0xc8(%rbp)
movl   $0x30,-0xc4(%rbp)
lea    0x10(%rbp),%rax
mov    %rax,-0xc0(%rbp)
lea    -0xb0(%rbp),%rax
mov    %rax,-0xb8(%rbp)
```

上方的汇编代码的开场白是两条`movl`指令，它将0x8和0x30两个值压到栈上，这两个数值是特殊的，在X86中一般都是固定的，其中0x8代表`gp_offset`，0x30代表`fp_offset`。

然后会将地址`rbp + 0x10`放入`rax`内，一般来讲函数内部都是通过`rbp - xx`的方式操作栈上数据的，但这里使用的确实加法，本次加法跳过了返回地址和父函数的`rbp`，要知道函数调用发生前`rbp`上被存入了寄存器无法存放的形参，显然这里就是获取这些参数。

`lea`之后会通过`mov`将父函数存放形参的地址放到`rbp - 0xc0`的位置。

最后程序会复刻上一次`lea`和`mov`，将地址`rbp - 0xb0`存放到`rbp - 0xb8`的位置上，这个操作是做什么呢？

从上面的操作可以观察到一个事实，就是上面多个参数放入栈的位置其实是紧挨的。

```
c8 c4 c0 b8
```

假如对`rbp - 0xc8`地址进行观察，该地址其实就是`va_list`变量的地址，所以`va_start`，其实就是对`va_list`变量进行赋值。

```
p /x $rbp-0xc8
$3 = 0x7fffffffde18

p &valist
$1 = (va_list *) 0x7fffffffde18

(gdb) x /4gx 0x7fffffffde18
0x7fffffffde18: 0x0000003000000008      0x00007fffffffdef0
0x7fffffffde28: 0x00007fffffffde30
```

此时我们就知道了`va_start`是如何初始化`va_list`的。

#### va_arg

`va_arg`接口的作用是获取形参。

```
| c8        | c4        | c0                | b8            |
| gp_offset | fp_offset | overflow_arg_area | reg_save_area |
```

GCC针对`va_arg`生成的汇编代码分成四个部分。

第一部分是判断需不需要从寄存器保存区域取出数据，首先会根据取出数据的类型看是从`gp_offset`还是`fp_offset`拿偏移值，拿到偏移值后会将它根据0x2f或0xaf进行比较，如果`ja`发现`CF`和`ZF`均为0（大于`gp_offset`或`fp_offset`）就会跳转。

根据0x2f和0xaf这两个数值比较，是因为它们代表着上限，当最新的`gp_offset`或`fp_offset`超出上限时，就说明寄存器保存的数据已经全部被检索完了。

```
a. mov    -0xc4(%rbp),%eax
b. mov    -0xc8(%rbp),%eax
a. cmp    $0xaf,%eax
b. cmp    $0x2f,%eax
ja     11ee
```

一般来讲是不会直接跳转的，跳转是处理溢出寄存器存储容量的参数。

处理寄存器保持的参数时，会先取出`reg_save_area`和`gp_offset`（也可以是`fp_offset`）两个信息，然后累加`reg_save_area`和偏移值得到数据。

完成数据的获取后，会将移动偏移值指向新的数据。

```
mov    -0xb8(%rbp),%rax
mov    -0xc8(%rbp),%edx
mov    %edx,%edx
add    %rdx,%rax

mov    -0xc8(%rbp),%edx
add    $0x8,%edx
mov    %edx,-0xc8(%rbp)
```

如果跳转到`11ee`处对溢出数据进行处理时，它会先取出`overflow_arg_area`的地址然后进行累加，并将累加后的新地址保存到0xc0处，最后再获取数据。

累加后保存的方式保证了地址指向的数据永远是最新的。

```
11ee：
mov    -0xc0(%rbp),%rax
lea    0x8(%rax),%rdx
mov    %rdx,-0xc0(%rbp)
mov    (%rax),%eax
```

#### va_end

GLibC对于`va_end`的解释是清理`va_list`，释放资源避免未定义行为出现。但实际上GCC也可能并不对它进行实现，因为可能没什么需要释放的。

因此`va_end`在大多数时候是做出任何操作的，不起任何作用。

## 字符串

字符串是由一个或多个字符组成的序列，C语言中双引号`""`内字符就是字符串，它以空字符`\0`作为结束符标志。

字符串中包含的字符分成三类，一是普通字符，二是转义字符，三是格式化占位符。

### 转义字符

字符串经常需要和转义字符打交道，所谓的转义字符就是指通过普通字符表达出特殊含义的，C语言中有三种情况需要进行转义，一是转义普通字符表示特殊操作（比如`\n`），二是普通字符被C语言占用，通过转义表示正常字符（比如`\"`），三是表示非10进制格式数据（比如`\xhh`）。

```
\n：表示回车
\"：表示双引号
\ddd：表示8进制数据ddd
\xhh：表示16紧张数据hh
```

总结来讲，就是通过识别`\`标志，确认转义字符的起始位置，然后将后续的字符按照特定的规则转换成特定的含义。

### 格式化占位符

格式化占位符的作用是增强字符串的灵活性，格式占位符一般需要匹配参数进行使用，通过格式化占位符的帮助，我们可以非常灵活的将各种参数与字符串组合在一起。

含有格式化占位符的字符串被称作是格式化字符串。

在介绍格式化占位如何完成灵活性的任务之前，我们先来看一下它的语法。

```
%[parameter][flags][field width][.precision][length]type
```

`%`是格式化占位符的起始标志。

`parameter`指的是`k$`，它的作用是指定第`n`个参数进行打印，`$`是标识符，检索到`$`就会通过`$`前的数据作为索引值，`parameter`是可以不填写的。

`flags`指的是参数合进字符串时的格式信息，`flags`是可以不填写的。

```
+：显示数值的正负符号
	%+d, 2 -> +2 ; %+d, -2 -> -2

空格：使用空格填充数值的正负符号，+的优先级更高
	% d, 2 -> 空格2

-：设置为左对齐，默认右对齐
	%-4d, 2 -> 2空格空格空格
	%4d, 2  -> 空格空格空格2

#：对于g和G来讲，保留0表示精度；对于f、F、e、E、g、G来讲，会保留小数点；对于o、x、X来讲，会自动填充O、0x、0X表示进制格式

0：使用0填充宽度
	-> %04d -> 0002
```

`field width`指的是最小输出宽度，`precision`则负责最大输出宽度（不会截断整数类型，限制浮点类型小数右侧显示位数），它们都可以不填写。

```
%01.2s, "22222" -> 22
```

`length`的作用是指定数据类型的大小，常见的有`hh`、`l`等等，也是可以不填写的。

```
%hhu, 22222 -> 206
	-> 十进制：22222 -> 二进制：0101 0110 1100 1110
	-> hh -> 1字节 -> 二进制：1100 1110 -> 十进制：206
```

最后一个`type`是最重要的，因为它必须填写。它的的作用是指定接收参数的数据类型，常见的数据类型有`d`、`f`等等。

在众多的数据类型中有一个特殊的存在，就是`n`，对于`%n`来讲，它的作用是将已经成功输出的字符写入整形指针变量内。

#### 格式化字符串的组合

C语言最常见格式化字符串整合函数就是`printf`，它接受的第一个参数是格式化字符串，其余参数为格式化字符串所需要的参数。

```
int printf(const char* format, ...)
```

`printf`函数将格式化字符串与参数完成组合后，会将结果输出到标准输出`stdout`中。

从下方的示例中可以看到，`printf`函数接受了两个参数，

```
printf("%s - buwula", "wula!");
	-> wula! - buwula
```

除了借助`printf`这样的打印函数外，我们也可以选择借助`vsnprintf`函数，将组合好的格式化字符串放入缓冲区变量内，但不输出到某某文件中。

```
test(const char* fmt, ...)
	-> va_list args;
	-> va_start(args, fmt);
	-> vsnprintf(buf, BUFSIZE, fmt, args);
	-> va_end(args);
```

#### 标准输入与输出

`stdin`、`stdout`、`stderr`属于标准输入输出，其中`stdin`的作用是响应键盘的输入，`stdout`、`stderr`将内容输出到屏幕，即它们对于Linux而言是外部设备，在秉承一切皆文件原则的Linux中，它们作为设备文件存在于`dev`目录下。

`stdout`和`stderr`的区别在于缓冲区，`stdout`只有当缓冲区满了及遇到换行符的情况下才会输出信息，而`stderr`则是直接输出。

```
ls /dev/ | grep std
stderr
stdin
stdout
```

对于已经打开的文件，Linux会给它们分配文件描述符，进程可以通过文件描述符对文件进行操作。`stdin`、`stdout`、`stderr`对于的文件描述符分别是0、1、2。

```
ls /proc/self/fd/
0  1  19  2  20  23  27  3
```

比如某个程序当中含有大量的`printf`函数，而你有时候不需要打印，更不需要将打印输出到屏幕上，那么就可以在函数的开头通过`stdout`的文件描述符1，将`stdout`关闭（`close(1)`），那么就不会再看到输出了。

#### printf函数的实现

GLibC中对`printf`函数的实现如下，我们可以看到它与上方的`vsnprintf`示例非常相似。

```
__printf
	-> va_list arg;
	-> va_start (arg, format);
	-> __vfprintf_internal (stdout, format, arg, 0);
	-> va_end (arg);
```

从上方的函数名`__printf`函数可以发现，按照道理来讲，动态链接时根据字符串`printf`进行匹配时应该匹配不到`__printf`啊！

这其实是因为GLibC通过`ldbl_strong_alias`将`printf`设置成了`__printf`的别名。

```
ldbl_strong_alias (__printf, printf);
```

`ldbl_strong_alias`的别名绑定实际是通过GCC的`__attribute__`和`alias`关键字实现的。它会先借助`__typeof`获取`printf`函数的返回值类型，然后根据类型声明一个` extern void printf`的函数，最后通过`__attribute__`和`alias`将`printf`设置成了`__printf`的别名。

```
#define _strong_alias(name, aliasname) \
	extern __typeof (name) aliasname __attribute__ ((alias (#name))) __attribute_copy__ (name);
#define strong_alias(name, aliasname) _strong_alias(name, aliasname)
#define ldbl_strong_alias(name, aliasname) strong_alias (name, aliasname)
```

`__printf`中组合格式化字符串的关键在于`__vfprintf_internal`，

```
int vfprintf (FILE *s, const CHAR_T *format, va_list ap, unsigned int mode_flags);
```

`vfprintf`内部虽然为了处理格式化字符串做的非常复杂，但还是免不了使用`va_arg`。

```
vfprintf
	-> printf_positional
		-> va_arg
```

虽然`vfprintf`内部实现并没有进行解析，但是有一点是明确的，即它仍会根据字符串的结束符`\0`辨别是否结束，在`\0`之前的所有的格式化占位符`%`都会被解析出来，然后根据格式化占位符的要求利用`va_arg`查找数据。

#### 字符串结束符的问题

在C语言中，一般都会通过空字符`\0`判断字符串是否结束的，这个问题常常会带来一些烦恼，最常见的烦恼就是地址使用问题。

使用地址出现烦恼的原因并不复杂，即地址中存在`0x00`字节，该字节就是`\0`，因此当C语言解析地址时，如果碰到`0x00`就会自动截断，导致地址不全或没有地址。

```
32位：0x0804a028
32位：0x08000400
64位：0x00000000004000de
64位：0x0000000000404000
```

地址中的`0x00`字节无非出现在3个位置中，一是位于有效地址的起始字符前，二是位于有效地址的末尾，三是位于有效地址的中间。

在32位系统当中，地址会占用全部的32个比特位。这个时候情况会更好一些，因为只有2和3两种情况需要考虑，情况1根本就不会出现。

在64位系统当中，地址一般只会使用48个比特位，这个时候情况会更差一些，因为三种情况都需要考虑到。

下方给出了一段针对三种情况进行打印的示例代码。

```
typedef struct _print_str {
	char* desc;
	char* str;
	char* str_bytes;
} print_str;

static void addr_with_null_analyze(void)
{
	int cnt;
	print_str addr_null_prt[] = {
		{
			.desc = "0x00 before the effective address\0",
			.str = "0x0000444444404545\0",
			.str_bytes = "\x45\x45\x40\x44\x44\x44\x00\x00\0",
		},
		{
			.desc = "0x00 at the end of effective address\0",
			.str = "0x4444444444404500\0",
			.str_bytes = "\x00\x45\x40\x44\x44\x44\x44\x44\0",
		},
		{
			.desc = "0x00 in the effective address\0",
			.str = "0x4444444444400045\0",
			.str_bytes = "\x45\x00\x40\x44\x44\x44\x44\x44\0",
		},
	};

	cnt = sizeof(addr_null_prt) / sizeof(print_str);
	while (cnt > 0) {
		printf(
			"desc: %s\n"
			"\torig: %s\n"
			"\tbytes: start-%s-end\n",
			addr_null_prt[cnt - 1].desc,
			addr_null_prt[cnt - 1].str,
			addr_null_prt[cnt - 1].str_bytes
		);

		cnt--;
	}
}
```

从示例代码的输出结果中可以看到，当`\0`位于地址中部时，高位地址全部被截断了，当`\0`位于地址末尾时，整个地址都会被阶段，当`\0`位于地址开头时，地址是占不满64位的。

```
desc: 0x00 in the effective address
    orig: 0x4444444444400045
    bytes: start-E-end
desc: 0x00 at the end of effective address
    orig: 0x4444444444404500
    bytes: start--end
desc: 0x00 before the effective address
    orig: 0x0000444444404545
    bytes: start-EE@DDD-end
```

这个时候我们不难知道，想要通过C语言的相关字符串处理接口完整的处理地址可不是一件容易的事情，天大地大，内存空间何等广阔，地址难道就找不到一个容身之地吗？

先来看一下在地址的获取问题，怎么做可以保障完整性。

- 方法一：类似于`read`可以做到读取`\0`的函数。

- 方法二：通过小端字节序特性与字符数组初始化特性打出组合拳（只能处理情况1，即只有有效地址的起始字符前是`\0`）。

首先假设地址`0x0000000044404545`通过命令行参数传递给程序，这个时候如果发现命令行参数中含有空字符`\0`，它会发出一个警告，然后自动的帮助我们将`\0`清理掉。

```
bash: warning: command substitution: ignored null byte in input
```

由于当前机器使用小端字节序的缘故，所以低位地址数据会存入高位地址中。

```
接收到的参数：0x44404545
内存布局：45 45 40 44 00
```

当我们通过`strncpy()`或`snprintf`等类似功能的函数，将接受到的参数向缓冲区变量复制时，仍会保持原数据的内存布局，完成复制后低位地址会保持全部是0的状态，显然我们可以观察到地址的完整性得到了保留。

```
复制后的内存布局：45 45 40 44 00 00 00 ...
使用时的地址：0x0000000044404545
```

对于`snprintf`这样实现拼接功能的字符串处理函数来讲，这种做法不只要求只有有效地址前含有`\x00`外，还需要地址是最后一个参数，因为只有这样才可以保证数组初始化特性生效。

## 漏洞的产生

从上方针对格式化字符串的相关描述中，我们可以看到`va_xx`起到了关键的作用，从`va_arg`的实现中，我们发现了一个重要的事实，就是它的检索数据分成两个区域，一是寄存器保存的数据，当经过`cmp`和`ja`的判断后，如果发现超出上限，就不会再对寄存器保持的数据进行检索。

接下来会将目标瞄准父函数栈上存储的溢出数据部分，针对这一部分，GCC生成的代码有一些小缺陷，就是它没有一个结束标记，什么时候结束检索是由程序控制的。

在一般情况下，函数的接收的首个格式化字符串参数都是在编译前就已经确认好的，与格式化匹配的参数也都是确认好的，这个时候一般不会出什么纰漏。

但是假如格式化字符串是可以由输入方定义的，那么格式化字符串就会产生，下方会针对数据读写两个方面阐述格式化字符串漏洞。

### 信息的泄露

当格式化字符串可以被自定定义时，假如我们构造右侧的字符串`"%llx|.....|%llx"`，其中包含10个`%llx`，但除了格式化字符串参数外，不再提供任何参数，那么前5个`%llx`它会打印调用者寄存器中存储的数据（格式化字符串参数不在`va_arg`需要获取的参数范围内），至于其余5个则会根据执行`va_arg`的函数获取，获取参数的起始地址是`rbp + 0x10`（一般对应调用函数的`rsp`）。

至于`va_arg`，它可不会管你提供了几个参数，只会按照既定的路线获取参数。

```
printf函数运行前的调用者寄存器信息：
(gdb) info registers rsi rdx rcx r8 r9
rsi            0x7fffffffe018      140737488347160
rdx            0x7fffffffe028      140737488347176
rcx            0x555555557dc0      93824992247232
r8             0x0                 0
r9             0x7ffff7fcf680      140737353938560

1号到5号泄露信息：
0x7fffffffe018 | 0x7fffffffe028 | 0x555555557dc0 | 0x0 | 0x7ffff7fcf680

va_arg函数时的栈信息：
(gdb) p /8gx $rbp+0x10
0x7fffffffdef0: 0x0000001000000010      0x0000555555556072
0x7fffffffdf00: 0x0000000000000001      0x00007ffff7df124a
0x7fffffffdf10: 0x0000000000000000      0x0000555555555241
0x7fffffffdf20: 0x0000000100000000      0x00007fffffffe018

6号到10好泄露信息：
0x1000000010 | 0x555555556072 | 0x1 | 0x7ffff7df124a | 0x0
```

当构造大量的`%llx`时，还需要考虑变量的缓冲区是否可以容纳它们，如果缓冲区变量的空间有些小，不足够泄露金丝雀和所需内存地址时，岂不是无法对漏洞进行利用？

格式化占位符中有一个特殊的存在，即`k$`，`k`代表一个数字，当该指示符添加时，就会打印第n个参数，那么这个时候就不需要构造大量`%llx`对栈上信息进行泄露了。

此时我们已经可以检索函数栈内以及相对更高栈区中的数据。

除了栈之外的内存数据，有没有办法读取到呢？

首先要明确一点，能读取任意地址上的内容是因为我们可以先栈区填充地址，之后就要从格式化占位符的`type`上着手，因为`type`决定了地址如何被解释，是读取栈上的地址数据呢，还是更深一步从栈上地址内的数据呢？

```
stack   | address |
address | value   |
```

- 拥有一个可以控制的栈数据区加上`%s`的辅助就可以达到这一个目的。

先来看一下栈数据区，假设我们向栈上数据区填入了一段完整地址，现在想要打印该地址上的数据，只需要使用`%k$s`读取就可以。

```
[address]%k$s
%k$s[address]
```

可能有人会好奇，为什么不用`%lx`或`%llx`打印呢，原因很简单因为它们根本打印不出来。

```
stack    -> 50 10 40 00 00 00 00 00
0x401050 -> 41 41 41 41 41 41 41 41 | AAAAAAAA |

%llx, stack -> *(unsigned long long*)(stack) -> 0x401050
%s, stack   -> *(char*)(0x401050)            -> "AAAAAAAA"
```

### 信息的篡改

上方介绍过格式化占位符中的`type`，格式化占位符支持的数据类型有很多，其中`%n`支持前面处理过的字符数量存入一个指针变量内。

从下方的示例中可以看到，由于`%n`之前通过`10`强制输出了10个字符（空白字符由0填充），所以变量`i`是数值也是10。

```
printf("%.10u%n\n", 1, &i);
printf("i = 0x%x\n", i);

输出结果：
0000000001 
i = 0xa
```

这个时候我们就可以通过`%k$n`向任意栈上地址写入数据了。

`%n`作为格式化占位符中`type`属性的一种类型，也是支持`length`属性的，下面展示了一些`length`元素与`%n`进行组合后的效果。

```
hhn：向宽度为1字节的区域写入数据
hn：向宽度为2字节的区域写入数据
n：向宽度为4字节的区域写入数据
ln：向宽度为8字节的区域写入数据
lln：向宽度为16字节的区域写入数据
```

通过`length`元素控制被写入区域的宽度，可以实现更加精确的写入控制。

这个时候，我们需要抛出与信息泄露时一样的问题，除了栈之外的内存数据，有没有办法进行写入呢？

当然也是可以的，保持与信息泄露时制定的方案一直就可以，这是因为`%s`和`%n`在打印时对于地址的处理都是一样的，只不过区别在于`%s`能写，而`%n`能读罢了。

### 非栈上的格式化字符串漏洞

非栈与栈最大的区别，当然就是字符串存放的内存区域类型不同，尽管`va_arg`仍是从寄存器和栈上获取数据，在其余可变参数正常提供给类似与`xxprintf`函数时，格式化字符串是在栈还是非栈上当前没有任何影响。

但是这一区别会影响格式化字符串漏洞的利用吗？

对于非任意地址读写是没有影响的，因为本来也就是读取栈上的数据，对于任意地址读写影响可以大了，因为设置的任意地址是跟随格式化字符串一起存在，存放在栈上时还可以检索到，存放到非栈上时应该怎么检索呢？

处理这个问题的关键在于，如何让自定义的地址被检索到，进而发挥它跳板的作用，泄露或篡改地址上的数据，我们可以从地址设置方式和地址检索方式两方面下手。

- 借助跳板先造地址再读写操作。

首先明确一点制造地址也是需要通过`%n`进行修改的，在前面已经知道了`%n`需要的是一个二连地址（地址1保存的地址2，然后修改地址2上的数据），因此直接将栈上保存的数据修改为一个可用地址肯定是不行。

```
| stack address1 | address2 |

%n, (stack address) -> *(address2) = xxx
```

此时我们知道，`address2`上的数据可以被`%n`修改，但`address2`则不行，但是如果`address2`本身就是栈区中的地址呢？

如果是这样的话，这意味着`address2`是一个合适的跳板，它可以间接的帮助我们实现栈上数据的修改。

```
target：address3

| stack | address1 : address2 |
		| address2 : "aaa"    |
staget 1（change stack address2 save value to address3）：
	%n, (stack address1) -> *(stack address2) = address3
staget 2（change target address3 to xxx）：
	%n, (stack address2) -> *(address3) = xxxx
```

当栈上数据被设置成目标地址后，我们就可以再次通过`%s`或`%n`实现任意地址的读写。

而且跳板地址在栈中并不会少见，比如`main`函数必备的命令行参数`argv`就具备这种特性。

进一步假设，如果`address2`中存储的是一个栈地址`address4`，那么通过`%n, (stack address2) [1]`可以起到修改`"aaa"`的作用。

```
target：address3

| stack | address1 : address2 |
		| address2 : address4 |
		| address4 : "aaaa"   |
```

上方所有的做法，最终目的都是为了实现读写某个栈地址上保存的数据，由于`%n`的限制，使得我们必须借助踏板地址（如果栈地址A保存的数据仍为栈地址，那么A就是踏板），由于踏板地址仍为栈地址的特性，使得我们可以通过`%n`实现读写栈地址上保存数据的目的。

当我们拥有一级踏板时（`stack_addr1->stack_addr2`），我们需要先修改`stack_addr2`中保存的数值为目标地址，再通过`%n, (stack_addr2)`读写目标地址上保存的数据。

当我们拥有二级踏板时（`stack_addr1->stack_addr2->stack_addr3`），我们可以直接通过`%n, (stack_addr2)`读写`stack_addr3`上保存的数据。

- 狸猫换太子，借助栈迁移将栈迁移到格式化字符串存储的区域上，完成迁移后，`va_arg`可以获取非栈上的数据。

```
non stack save -> format string

va_arg	-> use register && stack
		-> cannot get non stack info

stack -> migrate to non stack zone -> va_arg can get non stack info

va_arg
	-> rbp + 0x10
	-> new rbp address value in non stack zone
```
