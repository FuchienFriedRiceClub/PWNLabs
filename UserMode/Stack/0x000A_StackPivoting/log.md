# 初始栈迁移

在x64架构下，栈空间通过`rsp`和`rbp`寄存器进行标识，加入你想要分辨一个函数的序言或结语，那么栈空间操作会使一个很重要的标识信号，这是因为，当函数开始时，他需要先将父函数的`rbp`放入栈中保存，然后根据当前`rsp`更新为自身栈底指针（`rbp`），最后以`rsp`为标记分配栈空间，而函数返回时，则是进行反向操作，即先将分配的栈空间释放，再从栈上取出父函数栈底指针并恢复到`rbp`，最后根据栈上的返回地址返回到父函数。

```
函数调用时栈空间操作的最基本情况 ->

函数调用：
push xxx         # 函数返回地址压入栈内，此时rsp自动减去0x8

序言：
push %rbp        # 保存父函数栈底指针到栈内，此时rsp自动减去0x8
mov %rsp,$rbp    # 设置被调用函数的栈底指针
sub xxx,%rsp     # 分配栈空间

结语：
leave            # 相当于下方指令进行的操作
	mov %rbp,%rsp;   ## 释放之前分配的栈空间
	pop %rbp         ## 从栈上取出之前保存的父函数栈底指针到rbp，此时rsp自动加上0x8
ret              # 从栈上取出返回地址，然后返回，此时rsp自动加上0x8
```

栈几乎和函数形影不离，而且函数内部使用的局部变量、需要使用内存地址的变量都会被放入栈空间的内部。

针对于99%的情况，栈对于函数而言都是一个温顺的狗、懂事的猫、善良的鸟，正因如此函数对它有着无条件的信任，但是当栈被迁移到我们构造好的区域时，此时的形式就发生了翻天覆地的变化，函数与栈的关系就变成了东坡先生与狼、吕洞宾与狗以及郝建与老太太。

![HaoJian](./asserts/HaoJian.png)

好了，从目前来看可控制的栈给了我们无限的遐想（也可能是画了个大饼），只有把栈劫持，我们就已经无所不能了！

## 如何进行栈迁移

想要把栈空间迁移到指定的位置，核心的原理就是修改`rsp`和`rbp`寄存器的数值，让它们指向我们期望中的位置。

针对于栈的各种篡改操作，它们通常会在函数结束才会开始生效，这是它们依赖于`ret`指令对程序的执行流程进行控制，因此在以往的文章中，没有针对`leave`指令构造参数的情况，但是这次情况发生了一些改变。

当我们针对`leave`指令在栈上构造参数时，它会通过`pop rbp`改变`rbp`寄存器中的数值，不过好像没什么用啊！想要改变`rsp`寄存器中的数值（`pop`和`ret`指令都是从`rsp+xxx`处取数值的），需要`leave`指令中的`mov rbp,rsp`操作，但是它在`pop rbp`的后面啊！

那怎么办？再来一次？......再来一次！

此时将返回值设置成`leave`指令的地址，进行第二次`leave`操作时，`rsp`就会会变成之前`rbp`的数值。

# 示例讲解

栈迁移有一个前提要求，就是攻击者具有一段可知的可读可写内存区域，但是程序加载到内存后，具有可读可写权限的段基本只有一个，这个段存放都是数据（包括初始化、动态链接、全局数据、变量信息），再加上现在的程序往往都会开启部分或全部只读保护，开启只读保护的直接结果就是可读可写段内基本只有`.got.plt`节、`.data`节及`.bss`节处于可写的状态。

```
可读可写的5号段：
LOAD           0x0000000000002de8 0x0000000000403de8 0x0000000000403de8
                 0x0000000000000240 0x0000000000000248  RW     0x1000
05     .init_array .fini_array .dynamic .got .got.plt .data .bss

12号段添加的只读保护区域：
GNU_RELRO      0x0000000000002de8 0x0000000000403de8 0x0000000000403de8
                 0x0000000000000218 0x0000000000000218  R      0x1
12     .init_array .fini_array .dynamic .got
```

其中`.got.plt`节用于延迟绑定，`.data`节内存放着已经初始化的变量数据，`.bss`节存储着尚未初始化的变量数据，修改它们时最好谨慎一些，万一后续还要使用，就会导致程序出现异常。

不然看出，目前我们的处境是十分艰难的，可读可写的部分并不多，而且这些个可读可写的部分好像还不太好惹。

## 车到山前必有路

尽管那些可读可写的部分不太好改，但是由于目前的机器基本使用的都是页表机制，内存分配就算只是1字节，它都会单独占上一个页，Linux下页大小通常都是0x1000（4KB），在99%的情况下，`.got.plt`节、`.data`节及`.bss`节不管占用几个页，最后都会剩余一部分空间。

显然页中的剩余空间给了我们足够的利用空间，使得我们可以大展拳脚。

除了这个之外，你最好起到程序没有使用PIE功能，不然的话你是没有办法可利用的内存区域地址的，除非先对内存地址进行泄露。

## 如何写内存呢？

尽管目前借助`No PIE`的帮助，我们可以直接通过ELF文件获得一段可靠的可读可写内存区域，但是我们要怎么往这段内存中写入数据呢？

此处需要两点要求，一是程序内部会调用类似`read`的读取函数，二是读取函数会使用栈上的缓冲区变量，这样读取时就会往已经迁移的栈上写数据了。

## 示例 - 在迁移栈上构造ROP

程序保护措施如下所示。

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

cat /proc/sys/kernel/randomize_va_space 
2
```

```
0000000000401136 <vuln>:
  401136:       55                      push   %rbp
  401137:       48 89 e5                mov    %rsp,%rbp
  40113a:       48 83 ec 30             sub    $0x30,%rsp
  40113e:       48 8d 05 bf 0e 00 00    lea    0xebf(%rip),%rax        # 402004 <_IO_stdin_used+0x4>
  401145:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  401149:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  40114d:       48 89 c7                mov    %rax,%rdi
  401150:       e8 db fe ff ff          call   401030 <puts@plt>
  401155:       48 8d 45 d0             lea    -0x30(%rbp),%rax
  401159:       ba 40 00 00 00          mov    $0x40,%edx
  40115e:       48 89 c6                mov    %rax,%rsi
  401161:       bf 00 00 00 00          mov    $0x0,%edi
  401166:       e8 d5 fe ff ff          call   401040 <read@plt>
  40116b:       90                      nop
  40116c:       c9                      leave
  40116d:       c3                      ret

000000000040116e <main>:
  40116e:       55                      push   %rbp
  40116f:       48 89 e5                mov    %rsp,%rbp
  401172:       e8 bf ff ff ff          call   401136 <vuln>
  401177:       48 8d 05 95 0e 00 00    lea    0xe95(%rip),%rax        # 402013 <_IO_stdin_used+0x13>
  40117e:       48 89 c7                mov    %rax,%rdi
  401181:       e8 aa fe ff ff          call   401030 <puts@plt>
  401186:       b8 00 00 00 00          mov    $0x0,%eax
  40118b:       5d                      pop    %rbp
  40118c:       c3                      ret
```

从上面的反汇编结果中可以看到，`vuln`函数内部具有明显的栈溢出，缓冲区变量的大小是0x20，但`read`函数实际读取的大小是0x40，由于缓冲区变量到栈底大小是0x30，所以溢出只能允许我们在函数返回时控制`rbp`和`rip`，这里显然无法直接找到`system("/bin/sh")`的调用，因此只给一个控制`rip`的空间显然是不够的，这里需要借助栈迁移构造一片新的栈空间。

从ELF文件中可以看到，编译期规划的可读可写段中`.got.plt`节之前的区域会被`GNU_RELRO`变成只读状态，只有`.got.plt`节后的区域是可读可写的。

```
LOAD           0x0000000000002de8 0x0000000000403de8 0x0000000000403de8
                 0x0000000000000238 0x0000000000000240  RW     0x1000
05     .init_array .fini_array .dynamic .got .got.plt .data .bss

GNU_RELRO      0x0000000000002de8 0x0000000000403de8 0x0000000000403de8
                 0x0000000000000218 0x0000000000000218  R      0x1
12     .init_array .fini_array .dynamic .got
```

通过查看ELF文件内对节规划的内存布局可以知道，`.got`节之前的内容会占用一个页，`.got.plt`节会从0x404000开始，且`.got.plt`节到`.bss`节总共占用的空间也不会超过0x50，而它们又会占用一个页的空间（0x1000），因此还剩余0x950的空让我们进行利用。

```
Contents of section .got:
 403fc8 00000000 00000000 00000000 00000000  ................
 403fd8 00000000 00000000 00000000 00000000  ................

Contents of section .got.plt:
 403fe8 f83d4000 00000000 00000000 00000000  .=@.............
 403ff8 00000000 00000000 36104000 00000000  ........6.@.....
 404008 46104000 00000000                    F.@.....

Contents of section .bss:
 404020 00000000 00000000                    ........
```

### 新栈空间内的数据规划

首先第一步需要做的就是栈迁移，即利用第一次读取的机会，设置`rbp+0x0`的位置，不过返回地址应该如何设置呢？

再次设置`leave`指令的地址？我们需要构造ROP，小程序内部无法提供该有的指令给我们，因此需要把主意达到LibC的身上，但此时ASLR是开启的，我们对于LibC的基地址一无所知，因此需要先借助`puts`函数泄露地址（程序内部的`puts`函数从`rbp-0x8`的位置获取字符串）。

此时我们就有了返回地址的地点，即回到调用`read`函数的地方。首次读取时我们只需要设置`rbp+0x0`和`rbp+0x8`的位置，其余部分不需要管，这次也一样吗？（值得注意的是此时`rbp`中保存的数值就已经变成了我们之前设置的数值）

当然不是，为了完成ROP大业，我们需要在`rbp-0x8`的位置放置一个存储着LibC相关相关信息的地址，显然这里PLT中的跳转地址0x404000是非常合适的。

```
0000000000401030 <puts@plt>:
  401030:       ff 25 ca 2f 00 00       jmp    *0x2fca(%rip)        # 404000 <puts@GLIBC_2.2.5>
  401036:       68 00 00 00 00          push   $0x0
  40103b:       e9 e0 ff ff ff          jmp    401020 <_init+0x20>
```

拥有泄露LibC的数据之后，此时我们就有了当前`rbp+0x0`和`rbp+0x8`位置需要设置的数值，其中`rbp+0x0`还是假栈地址，而`rbp+0x8`则会指向调用`puts`函数的位置。

`puts`函数泄露完LibC地址之后，会再次调用`read`函数，这是对我们有利的。因为我们还有构造的ROP需要进行放置。

此时缓冲区中数据的设置，由返回时的`rsp`决定。第一步我们需要明白，函数返回时`rsp`寄存器中的数值会变成`rbp`中的数值+0x10（假栈地址+0x10），显然`rsp`没有指向我们设置的数据区，为了让`pop`和`ret`正常的工作，我们需要再进行一次`leave`操作，因此`rbp+0x0`需要设置为假栈地址-0x30的位置，`rbp+0x8`则指向`leave`指令的位置。

为了配合`rsp`的设置，第二次`leave`指令会将`rbp+0x0`中数值交给`rsp`，随后再`pop rbp`，最后再`ret`。`pop rbp`会从`rsp+0x0`的位置取出数值放入`rbp`内，因此`rsp+0x0`需要空出来，`rsp+0x8`之后的空间才是我们放置ROP的地方。
