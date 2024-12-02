# 利用思路

函数返回时，会存在寄存器指向存储变量的位置，其中最为常见的就是`rsp`寄存器，它永远指向当前程序栈顶的位置，除此之外，也可能存在其他的寄存器保存着缓冲区变量的位置。

`ret2reg`有两点要求，一是缓冲区变量可以容纳Shellcode，二是缓冲区变量所在的内存页是可以在执行的。

为了实现程序控制流的跳转，我们需要除了需要向缓冲区变量内注入Shellcode，还需要将函数的返回地址改成`call xxx`或`jmp xxx`指令的地址（`xxx`为寄存器）。

当然想要利用寄存器还有一点需要确认，就是寄存器的数值在函数返回时是可以使用的，而函数返回前就被覆盖了。

## 最可能利用的寄存器 - RAX

在x86_64架构中程序中，经常可以看到`rax`寄存器从栈上、只读区域等地方获取数值，对于GLibC来讲，调用的函数或跳转的位置常常是运行期才会完成确认，因此GlibC中就会经常看到，函数先取出数值到`rax`寄存器中，然后再通过`call`或`jmp`指令，调用`rax`寄存器内的信息。

通过GCC编译器产生的程序，在其最终生成的ELF文件内，经常可以看到GLibC插入的代码，这些代码直接给我们提供了`call rax`和`jmp rax`指令。

其中`_init`函数会使用`call rax`指令，该`rax`寄存器中数据的来源是ELF文件内的`.got`节，它会根据`PREINIT_FUNCTION`函数是否存在，然后进行调用。`PREINIT_FUNCTION`函数对应着`__gmon_start__`，当程序启用分析功能时，LD就修改`.got`节中数据，让程序再这里进行分析功能的初始化。

```
0000000000401000 <_init>:
  401000:       f3 0f 1e fa             endbr64
  401004:       48 83 ec 08             sub    $0x8,%rsp
  401008:       48 8b 05 c9 2f 00 00    mov    0x2fc9(%rip),%rax        # 403fd8 <__gmon_start__@Base>
  40100f:       48 85 c0                test   %rax,%rax
  401012:       74 02                   je     401016 <_init+0x16>
  401014:       ff d0                   call   *%rax
  401016:       48 83 c4 08             add    $0x8,%rsp
  40101a:       c3                      ret
```

除了`_init`函数之外，当然还有其他函数也具备`call rax`或`jmp rax`的特征，只要是符合调用运行期才会解析的函数的特点。

# 示例讲解

本程序的保护情况如下所示，不难看出当前程序没有任何的保护。

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x400000)
Stack:    Executable
RWX:      Has RWX segments
```

从程序的反汇编结果中可以看到，`vuln`是一个存在缓冲区溢出漏洞的函数，缓冲区变量拥有足够的空间容纳Shellcode，而且`fgets`函数的返回值就是缓冲区变量的所在地址，正好位于`rax`寄存器中，如果我们能找到`call rax`或`jmp rax`指令的所在地址，就可以让程序在返回时前往缓冲区变量，进而执行缓冲区变量内的Shellcode。

```
0000000000401146 <vuln>:
  401146:       55                      push   %rbp
  401147:       48 89 e5                mov    %rsp,%rbp
  40114a:       48 81 ec 10 01 00 00    sub    $0x110,%rsp
  401151:       48 8d 05 ac 0e 00 00    lea    0xeac(%rip),%rax        # 402004 <_IO_stdin_used+0x4>
  401158:       48 89 c6                mov    %rax,%rsi
  40115b:       48 8d 05 a4 0e 00 00    lea    0xea4(%rip),%rax        # 402006 <_IO_stdin_used+0x6>
  401162:       48 89 c7                mov    %rax,%rdi
  401165:       e8 e6 fe ff ff          call   401050 <fopen@plt>
  40116a:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  40116e:       48 83 7d f8 00          cmpq   $0x0,-0x8(%rbp)
  401173:       75 0f                   jne    401184 <vuln+0x3e>
  401175:       48 8d 05 95 0e 00 00    lea    0xe95(%rip),%rax        # 402011 <_IO_stdin_used+0x11>
  40117c:       48 89 c7                mov    %rax,%rdi
  40117f:       e8 ac fe ff ff          call   401030 <puts@plt>
  401184:       48 8d 05 98 0e 00 00    lea    0xe98(%rip),%rax        # 402023 <_IO_stdin_used+0x23>
  40118b:       48 89 c7                mov    %rax,%rdi
  40118e:       e8 9d fe ff ff          call   401030 <puts@plt>
  401193:       48 8b 55 f8             mov    -0x8(%rbp),%rdx
  401197:       48 8d 85 f0 fe ff ff    lea    -0x110(%rbp),%rax
  40119e:       be 00 10 00 00          mov    $0x1000,%esi
  4011a3:       48 89 c7                mov    %rax,%rdi
  4011a6:       e8 95 fe ff ff          call   401040 <fgets@plt>
  4011ab:       90                      nop
  4011ac:       c9                      leave
  4011ad:       c3                      ret

00000000004011ae <main>:
  4011ae:       55                      push   %rbp
  4011af:       48 89 e5                mov    %rsp,%rbp
  4011b2:       b8 00 00 00 00          mov    $0x0,%eax
  4011b7:       e8 8a ff ff ff          call   401146 <vuln>
  4011bc:       48 8d 05 65 0e 00 00    lea    0xe65(%rip),%rax        # 402028 <_IO_stdin_used+0x28>
  4011c3:       48 89 c7                mov    %rax,%rdi
  4011c6:       e8 65 fe ff ff          call   401030 <puts@plt>
  4011cb:       b8 00 00 00 00          mov    $0x0,%eax
  4011d0:       5d                      pop    %rbp
  4011d1:       c3                      ret
```
