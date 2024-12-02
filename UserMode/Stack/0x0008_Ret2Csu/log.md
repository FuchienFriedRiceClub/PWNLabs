# CSU的初印象

CSU的全名的`C Start Up`，对于GCC编译出来的程序来讲，静态链接程序需要通过`__libc_csu_init`完成初始化的工作，当然它并不会直接运行`main`函数，`main`函数的启动仍是由`__libc_start_main`函数负责的。

GLibC源代码的下载路径：

```
https://ftp.gnu.org/gnu/glibc/
```

对于GLibC版本小于2.34的版本来讲，由它生成的程序仍然是包含`__libc_csu_init`的，但是2.34版本以后，`__libc_csu_init`函数就已经消失了，这一改动的首要影响就是编译出来的文件内，文件中的二进制信息内不再含有`__libc_csu_init`函数了。

`__libc_csu_init`函数的源代码位于GLibC（<2.34）中`csu`目录下，对应的源代码文件是`elf-init.c`，所有的静态链接程序在最终的二进制信息中都会被插入这段代码。

```
2.33版本存在elf-init.c：
ls ./glibc-2.33/csu/
abi-note.c   dso_handle.c  errno.c      gmon-start.c  init-first.c  libc-tls.c  start.c         sysdep.c   Versions
check_fds.c  elf-init.c    errno-loc.c  init.c        libc-start.c  Makefile    static-reloc.c  version.c

2.34版本不存在elf-init.c：
ls ./glibc-2.34/csu/
abi-note.c   dso_handle.c  errno-loc.c   init.c        libc-start.c  Makefile  static-reloc.c  version.c
check_fds.c  errno.c       gmon-start.c  init-first.c  libc-tls.c    start.c   sysdep.c        Versions
```

## __libc_start_main的加载

对于GLibC来讲，不管是动态链接程序还是静态链接程序，其ELF文件头信息中的程序入口地址始终会指定`_start`函数，这是一段代码由GCC编译器插入进去的代码，`_start`函数标志着程序正式开始启动。

```
头信息：
Entry point address:               0x4004d0

00000000004004d0 <_start>:
   ......
   105f:       ff 15 5b 2f 00 00       call   *0x2f5b(%rip)
   ......
```

`_start`函数肩负起了程序启动的重任，它的主要职责就是就是调用`__libc_start_main`函数，调用的方式是`call`指令，`*0x..(%rip)`代表`rip+0x..`地址上数据，这段数据在编译时会位于可读可写段内，当程序开始运行时，最先运行的LD会将该地址上的数据设置为`__libc_start_main`函数地址，然后再将该段的前部分设置为只读状态，此时应用程序就可以正确的对`__libc_start_main`函数进行调用，且不能修改只读部分的内存信息。

```
5号段：
  LOAD           0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000248 0x0000000000000250  RW     0x1000

只读保护段（可以看到只读保护段与5号段部分重合）：
  GNU_RELRO      0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000230 0x0000000000000230  R      0x1

05     .init_array .fini_array .dynamic .got .got.plt .data .bss
```

这时我们将视线专注于`__libc_start_main`函数调用CSU的部分以及CSU负责的操作上。

## 最初的CSU（GLibC版本 < 2.34）

由于`__libc_csu_init`是和应用程序链接在一起的，所以函数地址在链接期就可以确定下来，`_start`函数只需要将函数的地址信息交给`rcx`寄存器，然后`__libc_start_main`函数的内部将`rcx`寄存器中的函数地址交给`r14`寄存器，最后通过`call`指令进行调用就可以了。

```
_start函数的赋值代码：
0x00000000004004e6 <+22>:    mov    $0x400620,%rcx

__libc_start_main函数调用的代码：
call   *%r14

r14寄存器信息：
info registers r14
r14            0x400620            4195872

__libc_csu_init函数地址信息：
info functions __libc_csu_init
0x0000000000400620  __libc_csu_init
```

`__libc_csu_init`函数的内部，首先处理的是寄存器参数，由于`r15`、`r14`、`r13`等寄存器原本是调用者占用的，考虑到在本函数（被调用者）内还需要使用这些寄存器，所以先将它们保存到栈上，等函数结束时再恢复过来，这样既不耽误被调用者对寄存器的使用，也不耽误返回时调用函数对寄存器的使用。

完成寄存器的数据处理后，`rbp`寄存器中的地址存储着`__do_global_dtors_aux`函数的地址，`r12`寄存器中的地址存储着`frame_dummy`函数的地址（这个两个函数都是编译器放入ELF文件内的），接下来会将`rbp`和`r12`中的地址相减并右移3位，右移3位相当于书中除以8，这个操作相当于获得一段区域占用的空间大小，然后根据单个元素的大小计算空间内的元素数量，暂时猜测这里的每一个元素都是地址（64位系统下的8位地址）。

通过查看ELF文件的节信息可以确定，`rbp`寄存器（地址：600e18）和`r12`寄存器（地址：600e10）分别对应`.init_array`节的结束和起始位置。

```
  [18] .init_array       INIT_ARRAY       0000000000600e10  00000e10
       0000000000000008  0000000000000008  WA       0     0     8
```

完成元素个数的计算后，会调用`_init`函数，在函数调用前后设置`edi`和`rsi`寄存器，是因为它们是调用者使用的寄存器，避免`_init`函数的内部改变寄存器数据，使得`__libc_csu_init`函数无法使用它们，`_init`函数也是GCC编译器将它假如到二进制文件内的，这里我们先略过它。

`_init`函数结束之后，就会根据元素个数决定是否进入循环，其中`test`指令是不改变操作数的与运算，只有操作数为0时才是假的，否则一直为真，已经循环的次数通过`ebx`寄存器统计，`add`和`cmp`指令使得`ebx`不断递增1并和总次数`rbp`进行比较。

循环体的内部，`rdi`、`rsi`、`rdx`负责传递三个参数，被调用的函数则由`r12`加上`ebx`乘8得到的地址决定的（每次偏移一个地址）。

```
0000000000400620 <__libc_csu_init>:
  400620:       41 57                   push   %r15
  400622:       41 56                   push   %r14
  400624:       49 89 d7                mov    %rdx,%r15
  400627:       41 55                   push   %r13
  400629:       41 54                   push   %r12
  40062b:       4c 8d 25 de 07 20 00    lea    0x2007de(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  400632:       55                      push   %rbp
  400633:       48 8d 2d de 07 20 00    lea    0x2007de(%rip),%rbp        # 600e18 <__do_global_dtors_aux_fini_array_entry>
  40063a:       53                      push   %rbx
  寄存器数据处理阶段，保存调用者使用的寄存器数据

  40063b:       41 89 fd                mov    %edi,%r13d
  40063e:       49 89 f6                mov    %rsi,%r14
  400641:       4c 29 e5                sub    %r12,%rbp
  400644:       48 83 ec 08             sub    $0x8,%rsp
  400648:       48 c1 fd 03             sar    $0x3,%rbp
  循环次数的计算

  40064c:       e8 27 fe ff ff          call   400478 <_init>
  函数调用

  400651:       48 85 ed                test   %rbp,%rbp
  400654:       74 20                   je     400676 <__libc_csu_init+0x56>
  400656:       31 db                   xor    %ebx,%ebx
  400658:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
  40065f:       00 
  400660:       4c 89 fa                mov    %r15,%rdx
  400663:       4c 89 f6                mov    %r14,%rsi
  400666:       44 89 ef                mov    %r13d,%edi
  400669:       41 ff 14 dc             call   *(%r12,%rbx,8)
  40066d:       48 83 c3 01             add    $0x1,%rbx
  400671:       48 39 dd                cmp    %rbx,%rbp
  400674:       75 ea                   jne    400660 <__libc_csu_init+0x40>
  400676:       48 83 c4 08             add    $0x8,%rsp

  下面操作对应寄存器数据处理阶段，用于还原调用者使用的寄存器数据
  40067a:       5b                      pop    %rbx
  40067b:       5d                      pop    %rbp
  40067c:       41 5c                   pop    %r12
  40067e:       41 5d                   pop    %r13
  400680:       41 5e                   pop    %r14
  400682:       41 5f                   pop    %r15
  400684:       c3                      ret
  400685:       90                      nop
  400686:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  40068d:       00 00 00
```

分析完上面的反汇编代码后，我们可以了解到`__libc_csu_init`函数的主要作用就是根据`.init_array`节中函数进行初始化。

## 后CSU时代（GLibC版本 >= 2.34）

当GLibC的版本来到2.34时，根据`.init_array`节进行初始化的操作当然还在，只不过将代码放到了动态链接库内，不再与二进制文件绑定在一起。

```
static void
call_init (int argc, char **argv, char **envp)
{
  /* For static executables, preinit happens right before init.  */
  {
    const size_t size = __preinit_array_end - __preinit_array_start;
    size_t i;
    for (i = 0; i < size; i++)
      (*__preinit_array_start [i]) (argc, argv, envp);
  }

# if ELF_INITFINI
  _init ();
# endif

  const size_t size = __init_array_end - __init_array_start;
  for (size_t i = 0; i < size; i++)
      (*__init_array_start [i]) (argc, argv, envp);
}
```

## 特殊的函数执行

上面提到过，CSU的初始化阶段，会从`.init_array`节中取出函数指针进行执行，如果我们将函数放入`.init_array`节，岂不是可以在`main`函数执行之前，进行一些特定的操作？

通过readelf工具的`-WS`参数观察ELF文件可以发现，ELF文件存在着`.init`、`.fini`、`.init_array`、`.fini_array`四个节的身影。

```
....
[12] .init             PROGBITS        0000000000401000 001000 000017 00  AX  0   0  4
[15] .fini             PROGBITS        0000000000401198 001198 000009 00  AX  0   0  4
....
[19] .init_array       INIT_ARRAY      0000000000403de8 002de8 000010 08  WA  0   0  8
[20] .fini_array       FINI_ARRAY      0000000000403df8 002df8 000010 08  WA  0   0  8
....
```

其中`.init_array`和`.fini_array`记录了函数指针。

```
Contents of section .init_array:
 403de8 30114000 00000000 36114000 00000000  0.@.....6.@.....

Contents of section .fini_array:
 403df8 00114000 00000000 4c114000 00000000  ..@.....L.@.....
```

`call_init`函数遍历`.init_array`节以及`_dl_call_fini`函数遍历`.fini_array`节时会根据表内记录的函数指针进行调用。

```
(gdb) bt
#0  befor_main_run () at main.c:6
#1  0x00007ffff7df1376 in call_init (env=<optimized out>, argv=0x7fffffffdfc8, argc=1) at ../csu/libc-start.c:145
#2  __libc_start_main_impl (main=0x401162 <main>, argc=1, argv=0x7fffffffdfc8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdfb8)
    at ../csu/libc-start.c:347
#3  0x0000000000401071 in _start ()

#0  after_main_run () at main.c:12
#1  0x00007ffff7fcc12a in _dl_call_fini (closure_map=closure_map@entry=0x7ffff7ffe2e0) at ./elf/dl-call_fini.c:43
#2  0x00007ffff7fcf81e in _dl_fini () at ./elf/dl-fini.c:114
#3  0x00007ffff7e0855d in __run_exit_handlers (status=0, listp=0x7ffff7f9c820 <__exit_funcs>, run_list_atexit=run_list_atexit@entry=true, run_dtors=run_dtors@entry=true) at ./stdlib/exit.c:116
#4  0x00007ffff7e0869a in __GI_exit (status=<optimized out>) at ./stdlib/exit.c:146
#5  0x00007ffff7df1251 in __libc_start_call_main (main=main@entry=0x401162 <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffdfc8) at ../sysdeps/nptl/libc_start_call_main.h:74
#6  0x00007ffff7df1305 in __libc_start_main_impl (main=0x401162 <main>, argc=1, argv=0x7fffffffdfc8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7fffffffdfb8) at ../csu/libc-start.c:360
#7  0x0000000000401071 in _start ()
```

`.init`和`.fini`是较为特殊的存在，它们会先于`.init_array`和`.fini_array`执行。

观察`.init`和`.fini`可以发现，这两个中记录的就是指令。

```
Contents of section .fini:
 401198 4883ec08 4883c408 c3                 H...H....

Contents of section .init:
 401000 4883ec08 488b05d5 2f000048 85c07402  H...H.../..H..t.
 401010 ffd04883 c408c3                      ..H...

0000000000401000 <_init>:
  401000:       48 83 ec 08             sub    $0x8,%rsp
  401004:       48 8b 05 d5 2f 00 00    mov    0x2fd5(%rip),%rax        # 403fe0 <__gmon_start__@Base>
  40100b:       48 85 c0                test   %rax,%rax
  40100e:       74 02                   je     401012 <_init+0x12>
  401010:       ff d0                   call   *%rax
  401012:       48 83 c4 08             add    $0x8,%rsp
  401016:       c3                      ret

0000000000401198 <_fini>:
  401198:       48 83 ec 08             sub    $0x8,%rsp
  40119c:       48 83 c4 08             add    $0x8,%rsp
  4011a0:       c3                      ret
```

GCC提供了`__attribute__`机制，它属于GCC指令，允许程序员在代码中设置函数属性、变量属性以及类型属性。

关于`__attribute__`机制详细用法可以查询GCC手册，这里要介绍的是`constructor`和`destructor`。

`constructor`会将指定的函数添加到`.init_array`节内，`destructor`会将指定的函数添加到`.fini_array`节内。

# 利用方向

从`__libc_csu_init`函数中可以知道，生成的汇编代码内存在着大量`pop`寄存器的操作，而且`ret`指令与它们相距很近，造成该现象的原因由两个，一是调用`.init_array`节中函数前有其他函数被调用（`_init`函数），二是`__libc_csu_init`函数会将接收到的参数直接进行传递，这就导致很多寄存器都有了先保存到栈后再恢复的操作。

在这大量的`pop`寄存器操作中，由于`pop r数值`的特殊性（最后一个字节对应寄存器的`pop`操作），使得可以利用的寄存器有获得了一次扩充的机会。

```
-----------------------------------
| 指令    | 字节 ; 指令    | 字节  |
| pop rax | 58  ; pop r8  | 41 58 |
| pop rcx | 59  ; pop r9  | 41 59 |
| pop rdx | 5a  ; pop r10 | 41 5a |
| pop rbx | 5b  ; pop r11 | 41 5b |
| pop rsp | 5c  ; pop r12 | 41 4c |
| pop rbp | 5d  ; pop r13 | 41 5d |
| pop rsi | 5e  ; pop r14 | 41 5e |
| pop rdi | 5f  ; pop r15 | 41 5f |
-----------------------------------
```

除了`pop`指令外，下面的`call`指令也是一段很好的利用区域。

```
  400660:       4c 89 fa                mov    %r15,%rdx
  400663:       4c 89 f6                mov    %r14,%rsi
  400666:       44 89 ef                mov    %r13d,%edi
  400669:       41 ff 14 dc             call   *(%r12,%rbx,8)
```

# 示例讲解

通过查看程序的反汇编结果可以知道，程序由`main`函数和`vulnerable_function`函数两个部分组成，其中`vulnerable_function`函数存在明显的溢出（缓冲区变量大小0x40，接收0x200），除此之外`main`函数中还存在一个`puts`函数，打印`rdi`保存地址上字符串。

```
00000000004005b7 <vulnerable_function>:
  4005b7:       55                      push   %rbp
  4005b8:       48 89 e5                mov    %rsp,%rbp
  4005bb:       48 83 ec 40             sub    $0x40,%rsp
  4005bf:       48 8d 45 c0             lea    -0x40(%rbp),%rax
  4005c3:       ba 00 02 00 00          mov    $0x200,%edx
  4005c8:       48 89 c6                mov    %rax,%rsi
  4005cb:       bf 00 00 00 00          mov    $0x0,%edi
  4005d0:       e8 db fe ff ff          call   4004b0 <read@plt>
  4005d5:       90                      nop
  4005d6:       c9                      leave
  4005d7:       c3                      ret

00000000004005d8 <main>:
  4005d8:       55                      push   %rbp
  4005d9:       48 89 e5                mov    %rsp,%rbp
  4005dc:       48 83 ec 50             sub    $0x50,%rsp
  4005e0:       89 7d bc                mov    %edi,-0x44(%rbp)
  4005e3:       48 89 75 b0             mov    %rsi,-0x50(%rbp)
  4005e7:       48 8d 3d ba 00 00 00    lea    0xba(%rip),%rdi        # 4006a8 <_IO_stdin_used+0x8>
  4005ee:       e8 ad fe ff ff          call   4004a0 <puts@plt>
  4005f3:       48 8b 05 46 0a 20 00    mov    0x200a46(%rip),%rax        # 601040 <stdout@GLIBC_2.2.5>
  4005fa:       48 89 c7                mov    %rax,%rdi
  4005fd:       e8 be fe ff ff          call   4004c0 <fflush@plt>
  400602:       b8 00 00 00 00          mov    $0x0,%eax
  400607:       e8 ab ff ff ff          call   4005b7 <vulnerable_function>
  40060c:       b8 00 00 00 00          mov    $0x0,%eax
  400611:       c9                      leave
  400612:       c3                      ret
  400613:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  40061a:       00 00 00 
  40061d:       0f 1f 00                nopl   (%rax)

0000000000400620 <__libc_csu_init>:
  400620:       41 57                   push   %r15
  400622:       41 56                   push   %r14
  400624:       49 89 d7                mov    %rdx,%r15
  400627:       41 55                   push   %r13
  400629:       41 54                   push   %r12
  40062b:       4c 8d 25 de 07 20 00    lea    0x2007de(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  400632:       55                      push   %rbp
  400633:       48 8d 2d de 07 20 00    lea    0x2007de(%rip),%rbp        # 600e18 <__do_global_dtors_aux_fini_array_entry>
  40063a:       53                      push   %rbx
  40063b:       41 89 fd                mov    %edi,%r13d
  40063e:       49 89 f6                mov    %rsi,%r14
  400641:       4c 29 e5                sub    %r12,%rbp
  400644:       48 83 ec 08             sub    $0x8,%rsp
  400648:       48 c1 fd 03             sar    $0x3,%rbp
  40064c:       e8 27 fe ff ff          call   400478 <_init>
  400651:       48 85 ed                test   %rbp,%rbp
  400654:       74 20                   je     400676 <__libc_csu_init+0x56>
  400656:       31 db                   xor    %ebx,%ebx
  400658:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
  40065f:       00 
  400660:       4c 89 fa                mov    %r15,%rdx
  400663:       4c 89 f6                mov    %r14,%rsi
  400666:       44 89 ef                mov    %r13d,%edi
  400669:       41 ff 14 dc             call   *(%r12,%rbx,8)
  40066d:       48 83 c3 01             add    $0x1,%rbx
  400671:       48 39 dd                cmp    %rbx,%rbp
  400674:       75 ea                   jne    400660 <__libc_csu_init+0x40>
  400676:       48 83 c4 08             add    $0x8,%rsp
  40067a:       5b                      pop    %rbx
  40067b:       5d                      pop    %rbp
  40067c:       41 5c                   pop    %r12
  40067e:       41 5d                   pop    %r13
  400680:       41 5e                   pop    %r14
  400682:       41 5f                   pop    %r15
  400684:       c3                      ret
  400685:       90                      nop
  400686:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  40068d:       00 00 00
```

当前程序来自于CtfHub中PWN技能树内的`rop`，保护情况如下所示。

```
cat /proc/sys/kernel/randomize_va_space 
2

Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

梳理一下我们现在能干些什么！

首先我们只知道ELF文件的地址，对堆栈及动态链接库的地址一无所知，其次由于金丝雀的确实，尽管栈是不可执行的状态，但我们可以肆无忌惮的利用ROP达到想要的目的，谁让是CSU提供给我们足够的利用空间并且让我们可以掌握了它的地址呢！
