栈上的缓冲区变量发生溢出时，可能会导致非预期情况（比如返回地址被劫持）的产生，进而导致一系列的安全问题。为了缓解该问题，Linux推出金丝雀机制`Stack Canaries`对栈进行保护，具体的保护原理会在下方进行分析。

# 金丝雀机制的检测逻辑

栈上的缓冲区变量溢出时，会向地址增高方向覆盖一段连续的区域，假如提前在栈底前放置1个随机数，那么当缓冲区变量溢出时，也会导致该随机数被篡改，假如当函数结束时，对之前保存的随机数进行检查，如果发现数值不对，就说明栈上的缓冲区变量溢出了。

从汇编角度上看，函数序言首先会向保存调用函数的栈底指针，然后设置被调用函数自身的栈底指针，最后分配栈空间，这3条汇编指令标志着1个经典的函数序言。

完成栈空间的基本设置后，金丝雀机制会让程序在局部变量的上方`rbp-0x8`添加随机值。

```
0x0000555555555159 <+0>:     push   %rbp
0x000055555555515a <+1>:     mov    %rsp,%rbp
0x000055555555515d <+4>:     sub    $0x20,%rsp

0x0000555555555161 <+8>:     mov    %fs:0x28,%rax
0x000055555555516a <+17>:    mov    %rax,-0x8(%rbp)
```

因为随机值会占用0x8字节的空间，所以局部变量的位置相对于未开启金丝雀机制前，也会增加0x8字节。

在函数返回时，金丝雀机制会先于`leave`指令及`ret`指令从栈上取出数据前，取出栈上保存的随机值并进行检查，只有当数值一致时，才会遵循正常的返回逻辑。

```
0x0000555555555187 <+46>:    mov    -0x8(%rbp),%rax
0x000055555555518b <+50>:    sub    %fs:0x28,%rax
0x0000555555555194 <+59>:    je     0x55555555519b <simple_overflow+66>
0x0000555555555196 <+61>:    call   0x555555555040 <__stack_chk_fail@plt>

0x000055555555519b <+66>:    leave
0x000055555555519c <+67>:    ret
```

通过观察随机值可以发现，最低字节刚好是`0x00`，由于C语言中字符串以`\0`作为结束符，所以即使缓冲区变量紧邻随机值且被填满时，字符串也会以随机值中的`\0`作为终止符，保证字符串被截断。

```
(gdb) x /gx $rbp-0x8
0x7fffffffde18: 0xabe7aa6352121c00
```

# 实现方式

在上面可以看到，随机数是从`fx+0x28`的位置取出的，那么这个值是谁放进去，怎么放进去的呢？

## 编译器的支持

为了支持金丝雀机制，在给代码文件生成二进制文件时，就需要在函数序言和结语部分插入上方展示的插入随机值及检测随机值的指令。

这些指令是否生成以及在什么情况下生成，可以通过编译选项进行控制，下面列举了GCC编译器的相关选项及说明。

```
-fstack-protector 只为局部变量中含有数组的函数开启保护
-fstack-protector-all 为所有函数开启保护
-fstack-protector-strong 为局部变量地址作为赋值语句的右值及函数参数、含有数组类型的局部变量、`register`声明的局部变量开启保护
-fstack-protector-explicit 对含义stack_protect attribute的函数开启保护
-fno-stack-protector 禁用保护
```

## TLS与金丝雀

LibC使用`fs`寄存器存放线程局部存储`TLS Thread Local Stroage`信息，TLS可用于支持多线程同时访问同1个全局变量或静态变量，保障不同线程间修改同一个全局变量或静态变量时不会产生冲突。

当然这种特殊的变量需要`__thread`关键字修饰，编译器看到`__thread`修饰的变量后，二进制文件内会将这些变量放入`.tdata `节和`.tbss`节内，前面的`t`用于标识`thread`，`.tdata `节和`.tbss`节中存储着变量的原始版本。

```
  [19] .tdata            PROGBITS         0000000000003dc0  00002dc0
       0000000000000010  0000000000000000 WAT       0     0     8
  [20] .tbss             NOBITS           0000000000003dd0  00002dd0
       0000000000000004  0000000000000000 WAT       0     0     4
  [21] .init_array       INIT_ARRAY       0000000000003dd0  00002dd0
```

TLS的实现由`tcbhead_t`结构体支持，在该结构体中存在`stack_guard`成员，他被用于存放随机数，该成员在结构体内的偏移值是0x28。

```
typedef struct
{
	void *tcb；
	dtv_t *dtv;
	void *self;
	int multiple_threads;
	int gscope_flag;
	uintptr_t sysinfo;
	uintptr_t stack_guard;
	uintptr_t pointer_guard;
	...
} tcbhead_t;
```

TLS由LD中的`init_tls`初始化，下面展示了完整的调用栈信息。

```
(gdb) bt
#0  init_tls (naudit=naudit@entry=0) at rtld.c:736
#1  0x00007ffff7fe9565 in dl_main (phdr=<optimized out>, phnum=<optimized out>, user_entry=<optimized out>, auxv=<optimized out>) at rtld.c:2040
#2  0x00007ffff7fe5146 in _dl_sysdep_start (start_argptr=start_argptr@entry=0x7fffffffdf50, dl_main=dl_main@entry=0x7ffff7fe6cc0 <dl_main>) at ../sysdeps/unix/sysv/linux/dl-sysdep.c:140
#3  0x00007ffff7fe69be in _dl_start_final (arg=0x7fffffffdf50) at rtld.c:494
#4  _dl_start (arg=0x7fffffffdf50) at rtld.c:581
#5  0x00007ffff7fe5748 in _start () from /lib64/ld-linux-x86-64.so.2
#6  0x0000000000000001 in ?? ()
#7  0x00007fffffffe269 in ?? ()
#8  0x0000000000000000 in ?? ()
(gdb)
```

在GDB中观察`fs`寄存器时，会发现`fs`寄存器的值永远是0，这是因为软件调试器GDB对系统寄存器没有访问权限导致的。但是内核提供了`arch_prctl`接口，用于修改或获取特定于体系结构的进程或线程状态。

在GDB中，已经借用内核接口将TLS所在位置放置在`fs_base`寄存器中。

```
fs             0x0                 0

fs_base        0x7ffff7db0740      140737351714624
(gdb) p *(tcbhead_t*)0x7ffff7db0740
$7 = {tcb = 0x7ffff7db0740, dtv = 0x7ffff7db10e0, self = 0x7ffff7db0740, multiple_threads = 0, gscope_flag = 0, sysinfo = 0, stack_guard = 16109256396036869120, 
  pointer_guard = 9142662214636680000, unused_vgetcpu_cache = {0, 0}, feature_1 = 0, __glibc_unused1 = 0, __private_tm = {0x0, 0x0, 0x0, 0x0}, __private_ss = 0x0, ssp_base = 0, 
  __glibc_unused2 = {{{i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{
        i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{i = {0, 0, 0, 
          0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{i = {0, 0, 0, 0}}, {i = {
          0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}, {{i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}, {i = {0, 0, 0, 0}}}}, __padding = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}}
```

初始化后`fs_base`会指向一段内存所在的区域，显然这段内存是专门提供给TLS使用的。

```
7ffff7db0000-7ffff7db3000 rw-p 00000000 00:00 0
```

## 金丝雀的产生

C程序启动时，操作系统会先将控制权交给LD，在LD执行好相应操作后，才会调用主程序的入口函数`_start`，想要调试LD程序也可以在`_start`函数处设置断点，因为`_start`函数是ELF文件的起点。

在通过`init_tls`初始化好TLS信息后，才会通过`security_init`产生随机值。随机值`stack_chk_guard`会根据另一个随机值`_dl_random`进行设置。

```
dl_main(.....)
{
	......
	init_tls(0)
	......
	if (__glibc_likely (need_security_init))
		/* Initialize security features.  But only if we have not done it
	    	earlier.  */
		security_init ();
	......
}

static void security_init (void)
{
	/* Set up the stack checker's canary.  */
	uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
#ifdef THREAD_SET_STACK_GUARD
	THREAD_SET_STACK_GUARD (stack_chk_guard);
#else
	__stack_chk_guard = stack_chk_guard;
#endif

	/* Set up the pointer guard as well, if necessary.  */
	uintptr_t pointer_chk_guard = _dl_setup_pointer_guard (_dl_random, stack_chk_guard);
#ifdef THREAD_SET_POINTER_GUARD
	THREAD_SET_POINTER_GUARD (pointer_chk_guard);
#endif
	__pointer_chk_guard_local = pointer_chk_guard;

	/* We do not need the _dl_random value anymore.  The less
	   information we leave behind, the better, so clear the
	   variable.  */
	_dl_random = NULL;
}
```

为了观察`_dl_random`，我们再GDB中`watch`该变量，当变量的数值改变时，调试器会自动中断，此时会发现随机值`_dl_random`由`_dl_sysdep_parse_arguments`函数设置。

`_dl_sysdep_parse_arguments`函数会通过`_dl_parse_auxv (GLRO(dl_auxv), auxv_values);`对`_dl_random`修改，`_dl_random`位于`auxv_values`中`AT_RANDOM`位置，而`auxv`是内核提供的一种接口，用于在程序运行时传递信息到用户空间，所以随机值`_dl_random`是内核产生的。

```
#0  _dl_sysdep_parse_arguments (start_argptr=<optimized out>, 
    start_argptr@entry=0x7fffffffdf50, args=args@entry=0x7fffffffde50)
    at ../sysdeps/unix/sysv/linux/dl-sysdep.c:93
#1  0x00007ffff7fe50e0 in _dl_sysdep_start (
    start_argptr=start_argptr@entry=0x7fffffffdf50, 
    dl_main=dl_main@entry=0x7ffff7fe6cc0 <dl_main>)
    at ../sysdeps/unix/sysv/linux/dl-sysdep.c:106
#2  0x00007ffff7fe69be in _dl_start_final (arg=0x7fffffffdf50) at rtld.c:494
#3  _dl_start (arg=0x7fffffffdf50) at rtld.c:581
#4  0x00007ffff7fe5748 in _start () from /lib64/ld-linux-x86-64.so.2
#5  0x0000000000000001 in ?? ()
#6  0x00007fffffffe26a in ?? ()
#7  0x0000000000000000 in ?? ()
```

`stack_chk_guard`随机值产生好后，会提交给`THREAD_SET_POINTER_GUARD`宏，该宏会对当前线程的线程描述符进行修改`stack_guard`成员，如果`THREAD_SET_STACK_GUARD`未被定义，那么随机值会被放入`__stack_chk_guard`全局变量内。

## 内核对不同线程的支持

操作系统内会有多个线程运行，不同线程间的金丝雀随机值显然应该是不同的，那么内核就需要为每个线程都保存一份金丝雀信息，当线程发生切换时，还需要将`fs+0x28`的数值进行更新。

在内核中每个线程通过`task_strcut`结构体进行管理，不同线程间通过`struct list_head tasks;`成员链表进行管理（对`tasks`成员进行遍历可以得到全部进程），在`task_strcut`结构体内存在`unsigned long	stack_canary;`成员，该成员在线程建立时由`dup_task_struct`获取随机值并填写该成员（前面`_dl_random`就是借助系统调用从这里获取数值的）。

```
struct task_struct {
	......
	struct list_head tasks;
	......
	unsigned long	stack_canary;
	......
}

static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
{
	......
	setup_thread_stack(tsk, orig);
	clear_user_return_notifier(tsk);
	clear_tsk_need_resched(tsk);
	set_task_stack_end_magic(tsk);
	clear_syscall_work_syscall_user_dispatch(tsk);

#ifdef CONFIG_STACKPROTECTOR
	tsk->stack_canary = get_random_canary();
#endif
	......
}
```

内核会通过`__switch_to`切换线程，这时候有个很重要的工作就是将保存当前线程的上下文，再将待切换线程的上下文设置好，上下文信息中就包含TLS信息，因此切换线程时，TLS信息也会随之更新，这样用户程序就可以访问寄存器获取正确的随机值了。

# 延迟绑定

从上面可以看到金丝雀的检测函数`__stack_chk_fail`来自LibC，而且类似于它一样来自动态链接库的函数，在函数名后都会有一个`@plt`的标识，这个标识起什么作用呢？

## 动态链接库中函数的绑定策略

在链接期中，链接器会将所有的目标文件和静态链接文件（多个目标文件的集合）中的内容链接进入自身，而动态链接库中的内容则会推迟到运行期时在进行绑定。

在动态链接的情况下，程序并不会在刚开始运行时就将全部的函数加载，而是采取按需加载的策略，即函数调用发生时再去加载。

## PLT与GOT的解析

通过`objdump`工具反汇编观察主程序的ELF文件可以发现，每个动态链接函数由于在文件内没有实际的函数实现，所以文件会先提供`.plt`节作为中转站，该节中的表项是动态链接函数跳转时的实际指向位置，`.plt`节中的每个表项都由3条指令组成。

```
0000000000001020 <puts@plt-0x10>:
    1020:       ff 35 ca 2f 00 00       push   0x2fca(%rip)        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:       ff 25 cc 2f 00 00       jmp    *0x2fcc(%rip)        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:       0f 1f 40 00             nopl   0x0(%rax)

0000000000001030 <puts@plt>:
    1030:       ff 25 ca 2f 00 00       jmp    *0x2fca(%rip)        # 4000 <puts@GLIBC_2.2.5>
    1036:       68 00 00 00 00          push   $0x0
    103b:       e9 e0 ff ff ff          jmp    1020 <_init+0x20>

0000000000001060 <read@plt>:
    1060:       ff 25 b2 2f 00 00       jmp    *0x2fb2(%rip)        # 4018 <read@GLIBC_2.2.5>
    1066:       68 03 00 00 00          push   $0x3
    106b:       e9 b0 ff ff ff          jmp    1020 <_init+0x20>

0000000000001169 <test>
	......
    118a:       e8 a1 fe ff ff          call   1030 <puts@plt>
	......
```

通过`readelf`工具观察段信息，可以知道`.plt`节位于`LOAD`可读可执行（RE）段内。

```
3号段：
LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000229 0x0000000000000229  R E    0x1000

03     .init .plt .text .fini
```

`.plt`节中除第一个表项外，其余表项都由`jmp push jmp`三条指令组成，第一条`jmp`指令指向`.got.plt`节，最后一条`jmp`指令都统一指向`.plt`中的首个表项，`push`指令会将表项的序号压入栈内。

通过`readelf`工具观察段信息，可以知道`.got.plt`节位于`LOAD`可读可写（RW）段内。

```
5号段：
LOAD           0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000260 0x0000000000000268  RW     0x1000

05     .init_array .fini_array .dynamic .got .got.plt .data .bss
```

首先分析第一条指令，该指令会指向`.got.plt`节中的不同表项，并根据表项内的数值进行跳转，`.got.plt`节中每8个字节（64位 / 8比特）为1个表项，表项中的数值会指向`.plt`节中表项`push`指令的所在位置。

```
jmp    *0x2fca(%rip) -> 0x1036+0x2fca = 0x4000 (36 10) -> 1036 push $0x0
jmp    *0x2fb2(%rip) -> 0x1066+0x2fb2 = 0x4018 (66 10) -> 1066 push $0x3

Disassembly of section .got.plt:

0000000000003fe8 <_GLOBAL_OFFSET_TABLE_>:
    3fe8:       e0 3d 00 00 00 00 00 00 00 00 00 00 00 00 00 00     .=..............
        ...
    4000:       36 10 00 00 00 00 00 00 46 10 00 00 00 00 00 00     6.......F.......
    4010:       56 10 00 00 00 00 00 00 66 10 00 00 00 00 00 00     V.......f.......
```

在等`push`指令将数据压入栈后，最后一条`jmp`指令会统一的跳转到`.plt`节中的首表项`<puts@plt-0x10>`。

```
.plt节中表项最后的jmp指令：
jmp    1020 <_init+0x20>

0000000000001020 <puts@plt-0x10>:
    1020:       ff 35 ca 2f 00 00       push   0x2fca(%rip)        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:       ff 25 cc 2f 00 00       jmp    *0x2fcc(%rip)        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:       0f 1f 40 00             nopl   0x0(%rax)

hexdump -C ./canary_bypass_example -s 0x3fc0 | more
00003fc0  03 00 00 00 00 00 00 00  c0 3f 00 00 00 00 00 00  |.........?......|
00003fd0  c0 2f 00 00 00 00 00 00  28 00 00 00 00 00 00 00  |./......(.......|
00003fe0  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
00003ff0  08 00 00 00 00 00 00 00  f9 00 00 00 01 00 00 00  |................|
```

通过上面的分析可以确定动态链接函数与`.plt`节、`.got.plt`节、`.got`节间的相互关系。但是这些节存在的意义仍不清楚，下面会结合调试器进行分析。

## 调试器下的观察动态链接过程

第一步：调用`puts`函数时先进入`.plt`节中对应的表项内。

```
(gdb)
0x000055555555518a      11              puts("hello world!");
1: x/i $rip
=> 0x55555555518a <example+33>:     call   0x555555555030 <puts@plt>
```

第二步：`jmp`指令指示从`.got.plt`节中获取跳转地址，因为函数是首次调用，所以`.got.plt`节中对应表项的跳转地址会指向`.plt`节中的`push`指令。

```
(gdb) 
0x0000555555555030 in puts@plt ()
1: x/i $rip
=> 0x555555555030 <puts@plt>:   jmp    *0x2fca(%rip)        # 0x555555558000 <puts@got.plt>

x /10x $rip+0x2fca
0x555555558000 <puts@got.plt>:  0x55555036      0x00005555      0x55555046      0x00005555
```

第三步：`push`指令将0x0（索引值）压入栈后，会继续根据`jmp`指令进行跳转。

```
(gdb) si
0x0000555555555036 in puts@plt ()
1: x/i $rip
=> 0x555555555036 <puts@plt+6>: push   $0x0
(gdb) 
0x000055555555503b in puts@plt ()
1: x/i $rip
=> 0x55555555503b <puts@plt+11>:        jmp    0x555555555020
```

第四步：观察跳转地址可以发现，`jmp`指令会带我们前往`.plt`节中的首表项。

```
(gdb) info files
0x0000555555555020 - 0x0000555555555070 is .plt
```

第五步：`.plt`节中的首表项会先将`.got.plt`节中待解析表项的地址压入栈内。

```
(gdb) info files
0x0000555555557fe8 - 0x0000555555558020 is .got.plt

(gdb) x /3i 0x555555555020
   0x555555555020:      push   0x2fca(%rip)        # 0x555555557ff0
   0x555555555026:      jmp    *0x2fcc(%rip)        # 0x555555557ff8
   0x55555555502c:      nopl   0x0(%rax)

(gdb) x /gx 0x555555557ff8
0x555555557ff8: 0x00007ffff7fdbe10

(gdb) info symbol 0x00007ffff7fdbe10
_dl_runtime_resolve_fxsave in section .text of /lib64/ld-linux-x86-64.so.2
```

此时可以发现`.got.plt`节中内容已经和之前静态文件中内容不同了。

压入栈的数据如下所示。

```
(gdb) x /10x $rsp
0x7fffffffddb8: 0xf7ffe2e0      0x00007fff      0x00000000      0x00000000
0x7fffffffddc8: 0x5555518f      0x00005555      0x00000019      0x00000050
0x7fffffffddd8: 0x00000000      0x00000000
```

第六步：执行`_dl_runtime_resolve_fxsave`函数，加载`puts`函数。

`_dl_runtime_resolve_fxsave`函数如何运作暂时就不做解析了。

第七步：再次执行`puts`函数时，会发现`.got.plt`节中表项存储的地址已经变成了`puts`函数的所在地址，此时执行`jmp`指令就会直接前往`puts`函数。

```
1: x/i $rip
=> 0x555555555030 <puts@plt>:   jmp    *0x2fca(%rip)        # 0x555555558000 <puts@got.plt>

(gdb) x /gx 0x555555558000
0x555555558000 <puts@got.plt>:  0x00007ffff7e327d0
(gdb) info symbol 0x00007ffff7e327d0
puts in section .text of /usr/lib/libc.so.6
```

## PLT与GOT的总结

在链接期内，动态链接函数其实现的所在位置是链接器不可知的，因此会提供过程链接表 `PLT Procedure Linkage Table`作为中转站，PLT会根据`.got.plt`节的指示跳转。

当动态链接函数尚未加载时，`.got.plt`节会指示`.plt`中的首表项，首表项会带我们前往前往解析函数，解析函数会找到动态链接函数并执行，同时也会修改`.got.plt`节中存放的函数地址，当动态链接函数再次被调用时，`.got.plt`节不再指示我们前往首表项，而直接带我们前往动态链接函数。

由于`.plt`节位于可读可执行段内，所以运行期中它是不可修改的，只能修改位于可读可写段中的`.got.plt`节，这也是该节存在的意义，否则直接省去`.got.plt`节就可以了。

# 绕过思路

## 泄露随机值

随机值的最低位设置为`\x00`，本意是为了保证字符串可以被`\x00`截断，从而保护其他字节信息。

但是这种假设是建立在缓冲区变量未溢出的前提下，当随机值的最低字节也被覆盖时，其余处于高位的字节信息也会被暴露出来。

## 检测函数的劫持

在上面的分析中可以看到，主程序中跳转到`__stack_chk_fail`函数的地址由`.got.plt`节中数据决定，并且`.got.plt`节在运行期是可以写的，假如该节中的内容被篡改，那么当运行`__stack_chk_fail`函数时，程序的执行流就会被我们控制。

# 示例讲解

下面直接给出了示例程序的源代码。

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define MAX_READ_LEN 4096

static void canary_leak(void) {
	char user_name[48];
    char password[12];

	puts("please enter user name: ");
	read(STDIN_FILENO, user_name, MAX_READ_LEN);
	printf("current user name: %s\n", user_name);

	puts("please enter password: ");
    read(STDIN_FILENO, password, MAX_READ_LEN);
}

static void stack_check_func_hijack(void)
{
	char buf[12];
	void* pointer;

	puts("please enter message: ");
	read(STDIN_FILENO, buf, MAX_READ_LEN);

	puts("please enter address: ");
	read(STDIN_FILENO, &pointer, MAX_READ_LEN);
	puts("please enter value: ");
	read(STDIN_FILENO, pointer, MAX_READ_LEN);
}

int main(int argc, char** argv)
{
	if (!argv[1]) {
		printf("need args..., will exit\n");
		return 0;
	}

	printf("printf address: 0x%lx\n", &printf);

	switch (argv[1][0]) {
	case 'c':
		goto TAG_CANARY_LEAK;
		break;
	case 'h':
		stack_check_func_hijack();
		break;
	default:
TAG_CANARY_LEAK:
		canary_leak();
		break;
	}

	printf("has return\n");

    return 0;
}
```

`canary_leak`函数内会读取两次输入，并且在首次输入后会将缓冲区变量打印出来，此时就可以利用它们泄露金丝雀，然后通过最后一次读取完成PWN。

`stack_check_func_hijack`函数内部会读取参数输入，第二次读取会导致变量A地址更改，因此可以将变量的内存地址修改为`.got.plt`节中`__stack_chk_fail`表项指向的地址，当`__stack_chk_fail`表项指向地址会决定被调用的函数是什么，第三次读取会修改变量A地址上的数据，它可以帮助我们绕过`__stack_chk_fail`函数的检查。
