编译器默认会将数据执行保护机制打开【Linux：`NX: No-Execute`，Windows：`DEP: Data Execution Prevention`】，该机制开启后，数据所在的内存页就会被标识为不可执行的状态。

由于栈上存放的都是数据，所以数据执行保护机制打开时，栈所在内存页会变成不可执行的状态，此时将Shellcode放在栈上，程序是没有办法执行Shellcode的。

对于GCC编译器来讲，编译选项`-z execstack`和`-z noexecstack`可以控制数据执行保护机制打开或关闭。

在Linux中，可以通过`maps`虚文件查看内存布局，下面列出了数据执行保护机制打开和关闭时，栈所在内存页的状态。

```
r: 可读, w: 可写, x: 可执行, p: 私有段, s: 共享段

开启数据执行保护机制：
7ffeffee2000-7ffefff03000 rwxp 00000000 00:00 0                          [stack]

关闭数据执行保护机制：
7fff4d273000-7fff4d294000 rw-p 00000000 00:00 0                          [stack]
```

# 数据执行保护机制的实现

数据执行保护机制需要软硬件协作实现。

## 硬件支持

对于现代CPU而言，通常会采用冯诺依曼架构，少数使用ARM-v7指令集的CPU会基于哈弗架构实现。两种架构的区别在于，哈弗架构中指令和数据的保存区域是分开的，数据区是不可执行的，而冯诺依曼架构中并没有将指令和数据进行区分。

基于冯诺依曼架构实现的CPU为了保障系统的安全性，采用添加不可执行位到页表中，使得内存管理单元`MMU Memory Manage Unit`可以控制页中数据的执行权限。

从上面的栈地址可以看到，起始和结束地址都是以`x000`作为结尾，一是Linux中默认分配的页大小为4KB（0x1000），二是使用页表机制分配的地址都会以页作为基础单位（最小就是一页），因此内存页的起始和结束地址都以`x000`结尾也就不奇怪了。

MMU不止支持操作系统设置页大小，不可执行位也是交给操作系统去配置的。在硬件支持不可执行位后，剩下的就是软件支持。

## 软件支持

首先面临的一个问题就是，操作系统从哪里得知应不应该设置不可执行位呢？

答案很简单，就是可执行文件，上面提到GCC的编译选项`-z execstack`和`-z noexecstack`会标识ELF是否开启数据执行保护机制。

ELF文件是Linux下可执行文件的标准格式，由ELF头信息、头表（段头表、节头表）信息、段信息、节信息组成。

其中ELF头信息描述整个ELF文件的基本信息（如字节序、文件类型、目标机器等等）。

不管是段还是节，都被划分成多个类型，不同的类型负责提供不同的功能，段和节分别用于在运行期和链接期提供支持。

不同类型段或节分布在ELF文件中的不同位置上，因此使用表结构去收纳它们，头表中会记录段或节的属性信息（其中包含段或节在ELF文件中的位置），段和节的具体内容并不会被收纳进去，所以可以根据头表找到具体的段或节，然后再获取其中的内容。

### GNU_STACK段的设置

操作系统加载可执行文件当然是运行期的事情，因此我们通过readelf工具的`-l`参数查看ELF文件的段头表信息，在列出的段中可以看到`GNU_STACK`段的存在，当数据执行保护机制打开时其段属性会被设置成不可执行状态，反之则会设置成可执行状态。

```
R: 可写, W: 可读, E: 可执行

开启数据执行保护机制：
GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
				0x0000000000000000 0x0000000000000000  RW     0x10

关闭数据执行保护机制：
GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
				0x0000000000000000 0x0000000000000000  RWE    0x10
```

### GNU_STACK的检测

Linux中一般借助`execve`函数启动程序，`execve`函数会发送系统调用给内核。

```
SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return do_execve(getname(filename), argv, envp);
}
```

当内核收到系统调用请求后，会先检查请求的文件是否具备执行条件，如果文件可以执行就会调用`load_binary`接口加载ELF文件。

```
static int search_binary_handler(struct linux_binprm *bprm)
{
	......
	retval = fmt->load_binary(bprm);
	......
}
```

在计算机中常常会有这样的情况，即一个目标可以由多种方式实现，这些实现即可能都需要加载，也可能视平台类型、硬件类型进行加载。为了更加方便的对不同的实现进行管理，Linux会为目标设置统一的接口，接口内部会细化目标需要完成的功能，然后实现与具体的成员进行绑定，当Linux要针对某目标操作某些功能时，就会直接调用对应的成员。

不同实现对应的接口之间通常会使用链表进行管理。

```
static struct linux_binfmt elf_format = {
	.module				= THIS_MODULE,
	.load_binary		= load_elf_binary,
	.load_shlib			= load_elf_library,
#ifdef CONFIG_COREDUMP
	.core_dump			= elf_core_dump,
	.min_coredump		= ELF_EXEC_PAGESIZE,
#endif
};
```

比如下面是Linux平台上著名的驱动初始化代码，不同的驱动其实现不同，实现对应的函数名也会不同，如果初始化驱动时，还需要提前把每个实现的初始化函数的函数名和地址记下，在进行调用会非常麻烦。

所以Linux中规定了驱动的函数类型必须为`int`，那么此时只需要将初始化函数绑定到对应的结构体并注册到链表中，在初始化驱动时只需要遍历链表，再调用统一的成员名就可以，而不需要思考其他的细节。

```
内核：我要加载驱动！！！
内核：怎么有这么多驱动啊，函数名还不一样，我要怎么样才能挨个调用！！！
内核：不如设置一种统一的接口，所有驱动都要按照接口的格式设置初始化函数，然后注册，然后我遍历链表，挨个调用就可以。
内核：具体你驱动内部怎么搞，我才不管呢！
```

```
按照统一格式设置初始化函数：
static int __init xxxx(void) { ...... }

static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++) {
		do_one_initcall(initcall_from_entry(fn));
	}
}

fn对应驱动初始化函数地址：
int __init_or_module do_one_initcall(initcall_t fn)
{
	......
	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);
	......
}
```

调用`load_binary`接口时，函数内部会检查段的类型及属性，其中就包含`GNU_STACK`段，然后根据`GNU_STACK`段的可执行属性设置`vm_flags`标志位，虚拟地址空间会根据该标志位设置页属性。

```
static int load_elf_binary(struct linux_binprm *bprm)
{
	......
	for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++)
		switch (elf_ppnt->p_type) {
		case PT_GNU_STACK:
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;

		case PT_LOPROC ... PT_HIPROC:
			retval = arch_elf_pt_proc(elf_ex, elf_ppnt,
						  bprm->file, false,
						  &arch_state);
			if (retval)
				goto out_free_dentry;
			break;
		}
	......
}

int setup_arg_pages(struct linux_binprm *bprm,
		    unsigned long stack_top,
		    int executable_stack)
{
	......
	if (unlikely(executable_stack == EXSTACK_ENABLE_X))
		vm_flags |= VM_EXEC;
	else if (executable_stack == EXSTACK_DISABLE_X)
		vm_flags &= ~VM_EXEC;
	......
}
```

# 绕过思路 - Libc取物

当我们观察最基本的C语言程序运行期的内存布局时，会发现C程序至少会依赖Libc、vDSO、LD三个动态链接库，并且这些动态链接库一定会存在可执行的部分，那么能否借助它们完成利用呢？

```
ldd ./example 
linux-vdso.so.1 (0x00007ffdb1ebb000)
libc.so.6 => /usr/lib/libc.so.6 (0x00007f8b16ed7000)
/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f8b170ec000)
```

结论一定是可以的，下面会介绍C程序会什么会依赖上述3个动态链接库。

## LD与LibC

在前面查看段头表时，可以看到`INTERP`段指定了`/lib64/ld-linux-x86-64.so.2`，并且发现它的格式还是动态链接库。

```
INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
				0x000000000000001c 0x000000000000001c  R      0x1
		[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]

file /lib64/ld-linux-x86-64.so.2
/lib64/ld-linux-x86-64.so.2: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), static-pie linked, BuildID[sha1]=c560bca2bb17f5f25c6dafd8fc19cf1883f88558, stripped
```

要知道现如今很难找到脱离动态链接库而产生的程序，即使程序内只包含`main`函数且`main`函数直接返回，这是其实是因为`main`函数并不是程序真正的起点。

先尝试一下不带`main`函数进行编译，这是会发现编译会报错，原因是链接过程中存在未定义的函数。从这里可以看出，在GCC编译器的眼中，`main`函数需要由`_start`函数调用，它是ELF文件真正的入口。

```
/usr/bin/ld: /usr/lib/gcc/x86_64-pc-linux-gnu/14.1.1/../../../../lib/Scrt1.o: in function `_start':
(.text+0x1b): undefined reference to `main'
collect2: error: ld returned 1 exit status
```

可以在GDB中可以设置下面的参数，对`main`函数前运行的情况进行调试。

```
set backtrace past-entry
set backtrace past-main
```

这里展示了调用`main`函数的完整调用栈信息。

```
(gdb) bt
#0  main () at main.c:14
#1  0x00007ffff7dd8c88 in __libc_start_call_main (main=main@entry=0x55555555516a <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffdf68)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#2  0x00007ffff7dd8d4c in __libc_start_main_impl (main=0x55555555516a <main>, argc=1, argv=0x7fffffffdf68, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdf58) at ../csu/libc-start.c:360
#3  0x0000555555555075 in _start ()
```

`_start`函数是GCC编译器插入ELF文件内的，它与程序静态链接在一起，`_start`函数会调用`__libc_start_main`函数，这就是使得程序必须与LibC建立关系，`__libc_start_main`函数会对`main`函数的建立与退出进行处理。

当通过GDB在`_start`函数设置断点时，会发现有2个断点被设置下来，首先命中的是LD（`INTERP`段指定）的`_start`函数，其次才是主程序的`_start`函数。

```
info b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   <MULTIPLE>         
        breakpoint already hit 2 times
1.1                         y   0x0000555555555050 <_start>
1.2                         y   0x00007ffff7fe5740 <_start>

Breakpoint 1.2, 0x00007ffff7fe5740 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) c
Continuing.
[Thread debugging using libthread_db enabled]                                       
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Breakpoint 1.1, 0x0000555555555050 in _start ()
```

由于现在的程序都依赖动态链接库，所以Linux会先将控制权交给动态链接器`ld-linux-x86-64.so.2`，LD会在主程序开始运行前进行预处理，其中有2个很重要的函数`dl_main`和`_dl_start_user`，`dl_main`函数负责解释`ld.so`参数并加载二进制文件和库，`_dl_start_user`函数负责跳转到主程序的入口点，然后把控制权交给主程序。

## vDSO

程序的运行需要使用处理器、内存等物理资源，而物理资源是由操作系统进行管理，因此程序必须向操作系统发出请求，该请求也被称作是系统调用。

早期的X86指令集中并没有专门给系统调用提供指令，所以Linux中采取软中断`int 0x80`的方式发起系统调用，缺点是软中断的调用耗时较长，尽管后续指令集中添加了系统调用指令（`32位：sysenter sysexit，64位：syscall sysret`），但是不同位下的系统调用的指令并不相同，这对于程序而言是困难的，因为它需要思考自己如何处理多系统调用指令带来的复杂度。

为了缓解该问题保障兼容性，Linux推出vDSO` vsyscall Dynamic Shared Object)`机制。在Linux内核中为了支持不同处理器的系统调用指令，Linux内核会针对不同的处理器生成相应的动态链接库，直到Linux启动时，选择与处理器对应的动态链接库进行加载。当程序运行时，Linux会将vDSO分享给程序，程序可以借助vDSO发起系统调用，而无需考虑处理器不同带来的兼容性问题。

## LibC借用

因为最基本的C语言程序也需要将LibC、vDSO、LD与自身进行动态链接，所以现代程序很难离开动态链接库，考虑到vDSO是内核提供的是虚拟副本且用于辅助系统调用，LD用于处理运行期的动态链接问题，它们都并不适合作为最直接利用对象。

而LibC作为C语言的标准库，其中具有很多常见函数的实际实现，且LibC中一定存在可执行的段，因此可以考虑将LibC作为合适的利用对象。

### 函数的借用

不管是通过readelf分析二进制文件，还是通过GDB在运行期查看函数，都可以很好的观察到当前LibC中函数实现。

```
readelf工具观察：
 readelf -s /usr/lib/libc.so.6 | grep execve
  1593: 00000000000e0fb0    37 FUNC    WEAK   DEFAULT   15 execve@@GLIBC_2.2.5
  2922: 00000000000e1550   102 FUNC    GLOBAL DEFAULT   15 fexecve@@GLIBC_2.2.5
  3065: 00000000000e0fe0    50 FUNC    GLOBAL DEFAULT   15 execveat@@GLIBC_2.34

GDB调试器观察：
(gdb) info functions 
All defined functions:

File main.c:
13:     int main(int, char **);
5:      static void simple_overflow(char *);

Non-debugging symbols:
0x0000555555555000  _init
......
0x00007ffff7fc7e10  getcpu
```

为了借助Libc运行期望的程序（比如打开一个shell），那么就需要借助LibC中携带的程序运行函数`system`或`execve`，其中`system`函数只需要1个参数并通过`shell`运行，而`execve`函数需要需要3个参数并会独立运行程序。

从使用角度上看，`system`函数无疑是最方便的。

### 指令的借用

除了完整使用某可执行区域的完整函数外，也可以进一步缩小范围，选择只借用部分指令。

# 示例讲解

示例程序是1个非常简单的程序，它会从标准输入中读取内容复制给缓冲区变量`buf`。

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define MAX_READ_LEN 4096

static void simple_overflow(void) {
    char buf[12];

    read(STDIN_FILENO, buf, MAX_READ_LEN);
}

int main(void)
{
	printf("printf address: 0x%lx\n", &printf);
    simple_overflow();

	printf("has return\n");

    return 0;
}
```

当前保护机制的启用情况如下所示。

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled

cat /proc/sys/kernel/randomize_va_space 
2
```

由于程序会泄露LibC中`printf`函数的地址，所以我们可以根据它获取到LibC在运行期的基地址。

## system函数地址的确认

为了让返回地址指向Libc中`system`函数的所在位置，就需要确认`system`函数在Libc中偏移。

通过`readelf`查看段头信息可以知道，LibC中共有4个可加载`load`段，其中1个`load`段是可执行的，想必`system`等其他函数也在其中。

```
ELF文件的结果：
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000738 0x0000000000000738  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000249 0x0000000000000249  R E    0x1000
  ......
```

ELF文件中存在着一张符号表，符号表内记录了全部的函数，`system`函数自然也在其中，通过readelf工具的`-s`选项，可以查看符号表中的全部内容。

```
readelf -s /usr/lib/libc.so.6 | grep system
1050: 0000000000050f10    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

当然没有readelf工具，也可以采用手工获取的方式，下面演示了如何手动进行解析。

手工解析ELF文件及详细了解ELF文件可以参考`/usr/include/elf.h`头文件及`https://refspecs.linuxfoundation.org/`官方文档。

下面手工查找时，字节对应的含义都可以通过上面的文档查找，readelf工具的主要作用就是按照文档对ELF文件中的字节信息进行语义翻译。

### 手工解析流程：

- A. 确认段头表的所在位置。

```
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00
7f: 特定标识
45 4c 46 = E L F
02：64位程序
01：小端字节序
01：默认版本
00：内核ABI版本-System V
00：ABI版本0
其余为保留字节
0000010  03 00 3e 00 01 00 00 00  60 5e 02 00 00 00 00 00
03：动态链接库文件
3e：机器类型X86-64
01：版本
25e60：入口地址
0000020  40 00 00 00 00 00 00 00  78 4d 1e 00 00 00 00 00
40：段头表起始位置
1e4d78：节头表起始位置
0000030  00 00 00 00 40 00 38 00  0e 00 40 00 3f 00 3e 00
00：无特定处理器信息
40：ELF头大小
38：段头表中单个表项的大小
0e：段头表表项数量
40：节头表中单个表项的大小
3f：节头表表项数量
3e：字符串表索引值
```

- B. 经过上面可以确认段头表的起始位置为0x40，单个表项大小为0x38，共有14个表项，下面会对目标段对应表项进行解析。

```
00000e8  01 00 00 00 05 00 00 00  00 40 02 00 00 00 00 00
01：LOAD
05：4-可读+1-可执行
24000：文件内的位置
00000f8  00 40 02 00 00 00 00 00  00 40 02 00 00 00 00 00
24000：虚拟地址
24000：物理地址
0000108  b9 b0 16 00 00 00 00 00  b9 b0 16 00 00 00 00 00
16b0b9：段大小
16b0b9：占用内存大小
0000118  00 10 00 00 00 00 00 00
1000：对齐值

可以发现上述解析是与readelf的结果是一致的
Type           Offset             VirtAddr           PhysAddr
				FileSiz            MemSiz              Flags  Align
LOAD           0x0000000000024000 0x0000000000024000 0x0000000000024000
				0x000000000016b0b9 0x000000000016b0b9  R E    0x1000
```

- C. 由于段中全部都是指令的二进制编码，所以无法直接看出哪个是`system`函数所处的部分。但链接期一定会对符号（其中当然包含函数名）进行解析，所以可以通过分析节信息获取`system`函数在文件内的偏移值。

C.1 .dynsym节分析

由于LibC是动态链接库，所以其符号应该放在`.dynsym`节中，而非`.symtab`节，在.`dynsym`节中表项占用0x18字节，表项中具有唯一性的标识符就是st_name，由于`st_name`只是索引值，所以需要先到`.dynstr`节中确认`system`名相对于`.dynstr`节的偏移值，然后根据偏移值查找`st_name`。

```
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
```

C.2 st_name索引数值确认

通过节头表可以确认`.dynstr`节的起始位置是0x17c68，从该位置开始索引，可以确认`system`字符串所在的位置是0x1aa18，相对于0x17c68偏移了0x2d80。

```
hexdump -C /usr/lib/libc.so.6 -s 0x17c68 | grep system
0001aa18  73 79 73 74 65 6d 00 67  65 74 64 69 72 65 6e 74  |system.getdirent|
```

C.3 system函数偏移确认

`.dynsym`节的起始位置是0x54b8，偏移后的位置就是0xb728，通过分析该区域的字节，可以确认是`system`函数所在表项，且结果可以与`readelf`工具读取的内容对应。

```
0000b728  b0 2d 00 00 22 00 0f 00  10 0f 05 00 00 00 00 00
2db0：st_name - system
22：st_info - STT_FUNC & STB_WEAK
00：st_other - STV_DEFAULT
0f：st_shndx
50f10：st_value
0000b738  2d 00 00 00 00 00 00 00
2d：st_size - 45

readelf工具读取结果
Num:  Value               Size Type    Bind   Vis      Ndx Name
1050: 0000000000050f10    45   FUNC    WEAK   DEFAULT  15  system@@GLIBC_2.2.5
```

通过对比ELF文件中`system`函数的字节数据与`system`函数反汇编指令的16进制结果，可以确认`system`函数已经被正确的找到了。

```
ELF文件数据：
00050f10  f3 0f 1e fa 48 85 ff 74  07 e9 72 fb ff ff 66 90
00050f20  48 83 ec 08 48 8d 3d 05  9f 15 00 e8 60 fb ff ff

GDB查看system函数反汇编结果的16进制格式：
<system>:        0xfa1e0ff3      0x74ff8548      0xfb72e907      0x9066ffff
<system+16>:     0x08ec8348      0x053d8d48      0xe800159f      0xfffffb60
```

此时就已经完成了对`system`函数地址的确认，之所以手工进行解析是非为了了解一些ELF文件的组成。

### sh字符串的确认

`system`函数需要接收1个字符串作为参数，这里选择`/bin/sh`作为参数，让其打开shell。通过`strings`工具可以快速进行解析，其中`-a`参数指搜索范围是整个文件，`-t`和`x`按照16进制格式打印字符串的位置。

```
strings -a -t x /usr/lib/libc.so.6 | grep "/bin/sh"
1aae28 /bin/sh
```

通过比对ASCII码可以指定`/bin/sh`对应`2f 62 69 6e 2f 73 68 00`，也可以在直接通过它对二进制文件进行检索。

```
hexdump -C /usr/lib/libc.so.6 | grep "2f 62 69 6e 2f 73 68"
001aae20  63 00 2d 63 00 2d 2d 00  2f 62 69 6e 2f 73 68 00  |c.-c.--./bin/sh.|
```

## 参数与函数调用

因为LibC中`system`函数是需要1个参数的，基于当前调用协议(`rdi rsi rdx rcx r8 r9`)，需要先将参数放入`rdi`寄存器中。

这个时候就需要借用某段可执行区域的部分指令了。但是问题来了，借用什么样的指令呢。

首先存放的目标是`rdi`寄存器，而存放的数值需要溢出到栈上，此时就需要借助`pop`指令从栈上取出输入放入`rdi`内，`pop`指令会从栈上取出最后1个数据，然后缩减栈顶。

在准备好待传递的形参后，就需要跳转到`system`函数，该函数的地址也是放到栈上的，那么这个时候就需要`ret`指令，`ret`指令的作用相当于`pop rip`。

指令的地址可以通过`ROPgadget`工具进行搜索，除此之外也可以借助指令对应的字节码进行检索。

```
ROPgadget工具检索结果：
ROPgadget --binary /usr/lib/libc.so.6 | grep "pop rdi ; ret"
0x00000000000fd8c4 : pop rdi ; ret
```

此时完整的利用链已经清晰了，可以参考下图。

![Exploit Chain](./asserts/ExploitChain.png)

### 拦路虎-段错误

当执行`exploit`后，会发现并没有弹出Shell，将GDB挂到程序上，会发现程序出现了段错误，段错误一般都是访问内存错误。

```
Program received signal SIGSEGV, Segmentation fault.

(gdb) x /i $rip
=> 0x7ffff7e03bf4:      movaps %xmm0,0x50(%rsp)
(gdb) p $rsp
$1 = (void *) 0x7fffffffdb08
(gdb) p $rsp+0x50
$2 = (void *) 0x7fffffffdb58
```

查看当前程序执行，在指令中操作的内存地址是`0x50(%rsp)`，通过查阅资料了解到`movaps`中`a`代表目标地址需要和16字节对齐，而此时的`0x50(%rsp)`是不能被16整除的，所以导致段错误。

16的16进制表示为0x10，所以内存地址的最后1位必须是0，上方地址的最后1位是0x8，为了让地址与16字节对齐，需要让原地址加8或减8。在上方操作`rsp`地址的指令为`pop`和`ret`，它们都让`rsp`的地址不断递增，因此这里可以考虑再次利用它们让`rsp`的地址加8。

增加1条指令再调用`system`函数，对于这种需求显然`ret`指令是最合适的。

## 成功PWN

执行`exploit`后会发现已经成功获得Shell。

```
$ whoami
test
$ exit
[*] Got EOF while reading in interactive
$ w
[*] Process './example' stopped with exit code -11 (SIGSEGV) (pid 3021)
[*] Got EOF while sending in interactive
```

### 程序的异常退出

但是当程序退出时，会发现程序因为异常退出，在GDB调试上观察，可以发现，程序退出时调用`ret`指令，但是`exploit`中`system`函数地址后并没有设置，因此`ret`会从栈上取出错误的地址并返回，如果在`exploit`内将LibC中`exit`函数的地址放到`system`函数地址后，使得`system`函数返回时可以从栈上取出`exit`函数，然后退出。
