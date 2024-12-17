# Dirty Pipe漏洞

## 跨进程通信

在现代计算机中，进程间内存空间往往是相互隔离的，相互隔离有相互隔离的好处，但这些独立的进程有时候也需要进行沟通，因此跨进程通信的需求就此产生，在Linux中跨进程通信的常见方式有共享内存、管道、消息队列等等。

`Dirty Pipe`漏洞就起源与管道。

## 管道通信的介绍

Pipe在Linux中也可以被称作是管道，是一种非常常见的跨进程通信方式，它的作用是链接写入数据进程和读取数据进程，其中读取进程的数据来源于写入进程。。

比如下面展示两条命令`cat`和`grep`，它们就通过管道符`|`连接在了一起，`cat`命令会读取`/proc/kallsyms`文件的内容输出到标准输出中，管道符会捕获输出并将输出交给`grep`命令，`grep`命令会对输出内容进行筛选。

```
cat /proc/kallsyms | grep -w "ksys_write"
ffffffffa47609c0 T ksys_write
```

`grep`命令的输入来自于`cat`命令的输出，管道符帮助`grep`实现了跨进程通信。对于`|`来讲，`xx | yy`中的`xx`是共享数据的写入端，`yy`是共享数据的读取端。

除了Shell提供的管道符之外，GLibC库也提供针对管道的支持，GLibC将`pipe`系统调用封装成`int pipe(int pipefd[2])`函数。

```
Linux内核系统调用：
#define __NR_pipe 22
#define __NR_pipe2 293

GLibC库函数：
int pipe(int pipefd[2])
```

其中形参`pipefd[2]`代表读写两端，读取端通过`pipefd[0]`获取数据，写入端通过`pipefd[1]`填充数据。

### 匿名管道与命名管道

最为常见的匿名管道就是Shell中的`|`，匿名管道的特点是只允许父进程产生子进程前创建管道，然后再创建子进程，此时子进程创建过程中会复制父进程的内存空间数据，管道文件的描述当然也在其中，子进程可以直接拿来使用，除了父进程和子进程外没人知道管道的文件描述符，所以称作是匿名管道`pipe`。

匿名管道保证数据的传输局限在父子进程的内部，其他进程想要获取管道内的数据就不行了，因此Linux提供命名管道`fifo`保障数据传输方案的通用性。

Linux中可以通过`mkfifo`或`mknod`命令快速的创建`fifo`，GLibC也封装了`mknodat`函数，让程序通过`S_IFIFO`参数创建`fifo`。

```
mknodat(AT_FDCWD, "tmp", S_IFIFO|0666)
```

观察`fifo`文件的属性可以发现，通过被用于标记是不是目录的最高位，在这里被标记成了`p`，显然`p`是不是区分管道文件和普通文件的关键所在。

```
ls -lh tmp 
prw-r--r-- 1 astaroth astaroth 0 Dec  4 11:19 tmp
```

### 匿名管道的创建

匿名管道属于特殊的文件系统`pipe`，`pipe`文件系统在系统启动时会进行注册。

```
init_pipe_fs
	-> register_filesystem(&pipe_fs_type)
```

用户态程序发出系统调用后，内核会通过`do_pipe2`函数处理匿名管道。

```
#define __NR_pipe 22
#define __NR_pipe2 293

sys_pipe - SYSCALL_DEFINE2 pipe
sys_pipe2 - SYSCALL_DEFINE2 pipe2

sys_pipe
sys_pipe2
	-> do_pipe2
```

`create_pipe_files`函数会先调用`get_pipe_inode`函数创建`inode`节点，然后再通过`alloc_file_pseudo`函数创建写入端文件，再复制出读取端文件。

回到`__do_pipe_flags`函数后，会通过`get_unused_fd_flags`函数分别给读写两端分配文件描述符。

完成文件描述符的分配工作之后，会通过`audit_fd_pair`更新当前进程的审计成员`audit_context`中的文件描述符元素。

最后就是通过`fd_install`函数将文件描述符和文件关联起来。

```
do_pipe2
	-> __do_pipe_flags
		-> create_pipe_files
			-> get_pipe_inode
				-> alloc_pipe_info
				-> inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR
			-> res[1] = alloc_file_pseudo
			-> res[0] = alloc_file_clone
		-> fdr = get_unused_fd_flags
		   fdw = get_unused_fd_flags
		   	-> __get_unused_fd_flags
				-> alloc_fd
		-> audit_fd_pair
			-> __audit_fd_pair
				-> audit_context
					-> return current->audit_context
				-> context->fds[0] = fd1;
				-> context->fds[1] = fd2;
	-> fd_install(fd[0], files[0])
	-> fd_install(fd[1], files[1])
```

给`pipe`创建节点的过程中，有一个很重要的操作就是给`i_mode`元素添加`S_IFIFO`标志位，这个标志位对于内核和用户态程序而言，是识别管道文件的关键。

从这里可以看到，匿名管道实际上就是利用一种只存在于内存中的伪文件进行通信，读取和写入端可以通过文件描述符，对内存数据进行方便快速的操纵。

### 内核操作管道的方式

管道文件创建时会指定`pipefifo_fops`作为操作接口。

```
get_pipe_inode
	-> inode->i_fop = &pipefifo_fops

create_pipe_files
	-> alloc_file_pseudo(......, &pipefifo_fops)
	-> alloc_file_clone(......, &pipefifo_fops)

const struct file_operations pipefifo_fops = {
	.open		= fifo_open,
	.llseek		= no_llseek,
	.read_iter	= pipe_read,
	.write_iter	= pipe_write,
	.poll		= pipe_poll,
	.unlocked_ioctl	= pipe_ioctl,
	.release	= pipe_release,
	.fasync		= pipe_fasync,
	.splice_write	= iter_file_splice_write,
};
```

#### 读取操作

管道文件的文件操作初始流程与普通虚文件的流程一致，都会通过`f_op->xxx`函数调用对应文件指定的操作函数。

```
ksys_read
	-> vfs_read
		-> new_sync_read
			-> iov_iter_ubuf
				->call_read_iter
					-> -> file->f_op->read_iter
```

首先我们看一下管道文件被读取时的情况，进入`pipe_read`函数后会先获取管道文件的信息`private_data`，`private_data`在节点创建过程中通过`alloc_pipe_info`函数进行分配，管道文件信息通过`pipe_inode_info`结构体描述。

拿完管道文件信息后，就会将信息暂时上锁，要知道这些信息是内核内部共享的，所以使用前最好先加锁告诉别人这个资源已经被使用了，等使用完后再解锁。

进入`for`循环后，会先获取管道文件缓冲区的起始标记`head`、结束标记`tail`以及缓冲区大小`mask`，然后判断缓冲区是否为空，如果不是就会开始读取数据。

读取时`pipe_read`函数会先从管道文件信息中获取缓冲区，然后通过`copy_page_to_iter`函数向用户态空间复制数据，最后解锁管道文件信息。

```
pipe_read
	-> struct pipe_inode_info *pipe = filp->private_data
	-> __pipe_lock
	-> for
		-> head = smp_load_acquire(&pipe->head)
		-> tail = pipe->tail
		-> mask = pipe->ring_size - 1
		-> !pipe_empty
			-> struct pipe_buffer *buf = &pipe->bufs[tail & mask]
			-> copy_page_to_iter
			-> tail++
			-> if (!pipe_empty(head, tail))
				-> countinue
	-> __pipe_unlock
```

管道的缓冲区通过`pipe_buffer`结构体描述，这个缓冲区是在创建节点时通过`alloc_pipe_info`进行分配的，它会分配`pipe_bufs`个`pipe_buffer`。在`pipe_read`函数的内部使用缓冲区数据时，它总是根据结尾标志在缓冲区内进行索引（`tail & mask`）（`ring_size`一定是2的n次幂，所以`ring_size - 1`的数值就相当于`b01...11`，使得`&`运算进行时多出的数值会被舍去，在`mask`范围内的数值则会全被留下）。

```
#define PIPE_DEF_BUFFERS 16

alloc_pipe_info
	-> unsigned long pipe_bufs = PIPE_DEF_BUFFERS
	-> pipe->bufs = kcalloc(pipe_bufs, sizeof(struct pipe_buffer), GFP_KERNEL_ACCOUNT)
	-> pipe->ring_size = pipe_bufs
```

通过`copy_page_to_iter`函数复制数据时，会先通过`iov_iter_is_pipe`检查传入数据的`struct iov_iter *i`的类型是不是`ITER_PIPE`，对于非`splice`方式发出的请求，类型一般都会设置成`ITER_UBUF`，此时内核会进入`_copy_to_iter`函数内，该函数内部仍会通过`iov_iter_is_pipe`辨别`splice`，如果不是就会通过`iterate_and_advance`宏复制数据，反之则通过`copy_pipe_to_iter`复制数据。

```
copy_page_to_iter
	-> iov_iter_is_pipe
		-> copy_page_to_iter_pipe
	-> _copy_to_iter
		-> iov_iter_is_pipe
			-> copy_pipe_to_iter
		-> iterate_and_advance(i, bytes, base, len, off, copyout(base, addr + off, len), memcpy(base, addr + off, len))
```

`copy_pipe_to_iter`和`copy_page_to_iter_pipe`有一些明显的区别。

`copy_pipe_to_iter`函数会先进入`append_pipe`函数，`append_pipe`函数的作用是给缓冲区数据找到物理内存页，这里分成两种情况，一是当前页还存在可以写入的空间，那么就会直接返回当前页，二是当前页空间不足时，就会通过`push_anon`分配新的匿名页。

`copy_pipe_to_iter`拿到物理页后，会通过`memcpy`进行数据复制。

```
copy_pipe_to_iter
	-> page = append_pipe
		-> if (offset > 0 && offset < PAGE_SIZE)
			-> pipe_buf
		-> push_anon
			-> alloc_page
	-> memcpy_to_page
		-> memcpy
```

`copy_page_to_iter_pipe`函数会先判断当前的偏移值是不是对应着最后一段数据的偏移值，如果是，就会通过`pipe_buf`取出当前的缓冲区数据，然后判断缓冲区数据用的页和当前页是否一致，如果一致就会更新缓冲区信息然后返回。

如果不是最后一段数据就会进入`push_page`内，通过`pipe_buf`获取当前缓冲区数据并设置，设置中有一个很重要的元素就是设置`page`。

```
copy_page_to_iter_pipe
	-> if (offset && i->last_offset == -offset)
		-> pipe_buf
			-> return &pipe->bufs[slot & (pipe->ring_size - 1)]
		-> if (buf->page == page)
			-> buf->len += bytes
			-> i->last_offset -= bytes
			-> i->count -= bytes
			-> return
	-> push_page
		-> pipe_buf
		-> *buf.page = page
```

#### 写入操作

与读取对应的还有写操作。

首先`pipe_write`函数会检查当前缓冲区队列是否为空，如果不为空且待写入数据的长度不为0，就会尝试判断当前页是否可以容纳新的数据且当前缓冲区数据允许合并新数据（存在`PIPE_BUF_FLAG_CAN_MERGE`标志位），如果可以就会将新数据合并进旧数据所在页内。

其中`buf->offset`是当前数据在页中的起始地址，`buf->len`是当前数据的长度，显然`buf->offset`和`buf->len`之和`offset`是当前数据在页内的结束地址，而`chars`则是新数据的长度，如果`offset + chars`小于页大小，那么就说明当前页是可以容纳新数据的。

当然可能有人会说页不是全部是空的吗，当然不是，`buf->offset`之前的空间都是不可用的。

```
pipe_write
	-> struct pipe_inode_info *pipe = filp->private_data
	-> __pipe_lock
	-> head = pipe->head
	-> was_empty = pipe_empty(head, pipe->tail)
	-> chars = total_len & (PAGE_SIZE-1)
	-> if (chars && !was_empty)
		-> mask = pipe->ring_size - 1
		-> struct pipe_buffer *buf = &pipe->bufs[(head - 1) & mask]
		-> offset = buf->offset + buf->len
		-> if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) && offset + chars <= PAGE_SIZE)
			-> copy_page_from_iter
```

如果新数据不能被完整的写入页内，内核就会进入循环对数据进行处理。

进入循环后，第一步做的就是拿到缓冲区数据，然后分配新页并将`head`递增1，新`head`会表明最新数据的位置，再之后会获取缓冲区数据，将它从用户空间复制到物理页当中。

```
pipe_write
	-> for
		if !pipe_full
			-> struct pipe_buffer *buf = &pipe->bufs[head & mask]
			-> !tmp_page
				-> alloc_page
			-> pipe->head = head + 1
			-> buf = &pipe->bufs[head & mask]
			-> copy_page_from_iter
```

管道数据的读写操作并不复杂，首先判断`tmp_page`是否存在，如果不存在就会分配新页，反之则会使用旧页，拿到可用的物理页后通过`copy_page_from_iter`会进行数据的写入操作。

`copy_page_from_iter`函数复制数据时，如果发现`ITER_PIPE`标志存在就会通过`WARN_ON`接口报一个警告信息（可以在`dmesg`中看到），反之则通过`iterate_and_advance`复制缓冲区数据。

```
copy_page_from_iter
	-> while
		-> _copy_from_iter
			-> if iov_iter_is_pipe
				-> WARN_ON
				-> return
			-> iterate_and_advance
```

#### 管道的缓存页

管道文件的读取和写入过程中都存在一个相似的问题，即物理页的使用问题，都分成使用默认页和自己分配页两种方式，但是读操作和写操作对在是否分配页的检查上有所差别。

先来看一下写操作，一般来讲创建的物理页都会通过`put_page`接口释放掉，但如果是匿名页情况就不同了，释放时会先检查物理页是不是存在且被自己独占，如果是就说明页可以被自己任意使用，因此会继续使用该页，反之则会释放掉。

```
pipe_buf_release
	-> ops->release

anon_pipe_buf_ops
	-> .release = anon_pipe_buf_release

pipe_write
	-> buf->ops = &anon_pipe_buf_ops;

anon_pipe_buf_release
	-> if (page_count(page) == 1 && !pipe->tmp_page)
		-> pipe->tmp_page = page
	-> else
		-> put_page
```

读操作时的情况会更加复杂一下，首先会根据`iov_iter_is_pipe`识别`ITER_PIPE`标志位。

```
copy_page_to_iter
	-> iov_iter_is_pipe
		-> copy_page_to_iter_pipe
	-> _copy_to_iter
```

`ITER_PIPE`标志位只有当`splice_read`发生时才会被赋值。

```
.splice_read = generic_file_splice_read

generic_file_splice_read
	-> iov_iter_pipe
		-> .iter_type = ITER_PIPE
```

检测到`ITER_PIPE`标志位后会进入`copy_page_to_iter_pipe`，此时`copy_page_to_iter_pipe`函数会直接使用上层传递过来的页。

如果没有`ITER_PIPE`标志位则会进入`_copy_to_iter`，`_copy_to_iter`函数内还会检查一次`ITER_PIPE`标志位（不一定只是`copy_page_to_iter`会调用），如果带有`ITER_PIPE`标志位则会进入`copy_pipe_to_iter`函数，该函数会检查传入的页是否可以容纳数据，如果可以就会使用原来的页，如果不可以就会分配新页再复制数据。

如果`_copy_to_iter`函数内不存在`ITER_PIPE`标志位，则会直接进行数据复制操作。

### iterate_and_advance

从上面我们可以知道，管道经常使用一种名叫`iterate_and_advance`的东西进行复制操作，但这是个什么东西呢？

`iterate_and_advance`接受7个参数，参数`i`对应IO向量`struct iov_iter`，参数`n`是数据长度，参数`base`、参数`len`以及参数`off`是`iterate_and_advance`内部创建的变量，至于参数`I`和参数`K`可以看作是两个函数调用。

首先从用户空间传上来的数据都会被打上`ITER_UBUF`的标志，此时会进入`iterate_buf`中。

```
#define iterate_and_advance(i, n, base, len, off, I, K) \
	__iterate_and_advance(i, n, base, len, off, I, ((void)(K),0))

#define __iterate_and_advance(i, n, base, len, off, I, K) {	\
	if (unlikely(i->count < n))								\
		n = i->count;										\
	if (likely(n)) {										\
		if (likely(iter_is_ubuf(i))) {						\
			void __user *base;								\
			size_t len;										\
			iterate_buf(i, n, base, len, off, i->ubuf, (I))	\
		}
		......
	}
}
```

`iterate_buf`会使用函数参数`I`，`I`一般对应`copyin`或`copyout`，当从用户空间复制数据到内核空间时会使用`copyin`，反之则使用`copyout`。

`copyin`还是`copyout`使用的函数是由架构决定的，比如X86架构就会使用`raw_copy_from_user`函数。

```
copyin
	-> raw_copy_from_user
		-> copy_user_generic

copyout
	-> raw_copy_to_user
		-> copy_user_generic
```

`raw_copy_from_user`函数最终会使用`copy_user_generic`函数。

```
static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}
```

`alternative_call_2`宏是一个用来使用体系结构某某特性的宏，如果CPU拥有特性2就使用特性2，拥有特性1就使用特性1，如果都没有就使用普通方式。

```
#define alternative_call_2(oldfunc, newfunc1, feature1, newfunc2, feature2, output, input...)	\
	asm_inline volatile (ALTERNATIVE_2("call %P[old]", "call %P[new1]", feature1,				\
		"call %P[new2]", feature2)																\
		: output,ASM_CALL_CONSTRAINT															\
		: [old] "i" (oldfunc), [new1] "i" (newfunc1),											\
		  [new2] "i" (newfunc2), ## input)
```

`copy_user_generic`复制数据参数为`=a =D =S =d`指定，`=a`是指定接收返回值的变量，`=D`是表明数据的目的地，`=S`是表面数据的来源，`=d`是指定复制长度。`"memory"`给编译器看的，代表这段汇编代码会修改内存，`"memory"`后面的寄存器是需要额外使用的寄存器。

这里我们假定通过CPU的特性2进行复制，此时`alternative_call_2`使用的函数就是`copy_user_enhanced_fast_string`，该函数是一段汇报代码。

```
SYM_FUNC_START(copy_user_enhanced_fast_string)
	ASM_STAC
	ALTERNATIVE "cmpl $64, %edx; jb copy_user_short_string", "", X86_FEATURE_FSRM
	movl %edx,%ecx
1:	rep movsb
	xorl %eax,%eax
	ASM_CLAC
	RET

12:	movl %ecx,%edx
	jmp .Lcopy_user_handle_tail

	_ASM_EXTABLE_CPY(1b, 12b)
SYM_FUNC_END(copy_user_enhanced_fast_string)
```

`copy_user_enhanced_fast_string`完成复制操作前后，会通过`ASM_STAC`和`ASM_CLAC`打开和关闭用户空间的数据访问权限。在X86中，保护用户空间数据访问权限的机制是特权模式访问保护`SMAP Supervisor Mode Access Protection`，当内核通过`X86_FEATURE_SMAP`检测到SMAP开启后就会使用`ASM_STAC`和`ASM_CLAC`。

```
#define X86_FEATURE_SMAP (9*32+20)

#define __ASM_CLAC	".byte 0x0f,0x01,0xca"
#define __ASM_STAC	".byte 0x0f,0x01,0xcb"

#define ASM_CLAC \
	ALTERNATIVE "", __ASM_CLAC, X86_FEATURE_SMAP
#define ASM_STAC \
	ALTERNATIVE "", __ASM_STAC, X86_FEATURE_SMAP
```

`rep movsb`是数据复制指令，如果数据复制过程中产生异常就会通过`_ASM_EXTABLE_CPY`处理，其中`1b`是异常发生处，`12b`是异常处理处。

```
_ASM_EXTABLE_CPY(from, to)	
```

在`iterate_buf`函数的内部，`STEP`参数对应的就是`I`，在执行`STEP`之前，会先设置`STEP`需要的形参，然后调用`STEP`执行复制操作。

```
#define iterate_buf(i, n, base, len, off, __p, STEP) {		\
	size_t __maybe_unused off = 0;				\
	len = n;						\
	base = __p + i->iov_offset;				\
	len -= (STEP);						\
	i->iov_offset += len;					\
	n = len;						\
}
```

### 有名管道的创建

有名管道与匿名管道的区别就在于，匿名管道是父子进程间共享的伪文件，而有名管道则是一个文件系统中真实存在的特殊文件，所有进程都可以感知它的存在。

有名管道通过`mknodat`系统调用进行创建。

```
#define __NR_mknodat 259
```

进入内核后，内核会通过`i_op->mknod`接口找到对应文件系统的节点创建函数。

```
sys_mknodat
	-> do_mknodat
		-> case S_IFIFO
			-> vfs_mknod
				-> i_op->mknod
```

这里以`ext4`文件系统作为示例进行分析。`ext4`文件系统会通过`__ext4_new_inode`在磁盘上创建一个真实的文件，如果检查发现创建的节点没有问题，就会通过`init_special_inode`，该函数的主要作用是指定节点的操作函数，这里检查发现用户态程序提交的参数是`S_FIFO`时，就会设置通过`pipefifo_fops`操作文件。

```
ext4_mknod
	-> ext4_new_inode_start_handle
	-> !IS_ERR(inode)
		-> init_special_inode
			-> if S_ISFIFO(mode)
				-> inode->i_fop = &pipefifo_fops
```

对于有名管道来讲，管道文件信息的创建是在文件打开时创建的。

```
pipefifo_fops
	-> .open = fifo_open

fifo_open
	-> alloc_pipe_info
```

### 管道的缓冲区

从上面可以看出，对于内核来讲，管道的信息被存储在`pipe_inode_info`结构体内，该结构体中的`head`成员和`tail`成员记录着缓冲区数据队列的起始位置，在队列中越新的数据在队列中的排名越靠后，显然管道数据是遵循先进先出的原则。

管道信息`pipe_inode_info`中的`bufs`成员管理着缓冲区数据。

```
pipe_inode_info
	-> struct pipe_buffer *bufs
```

`bufs`是一个数组，数组元素的个数是`PIPE_DEF_BUFFERS`决定的。

```
alloc_pipe_info
	-> unsigned long pipe_bufs = PIPE_DEF_BUFFERS
	-> kcalloc(pipe_bufs, sizeof(struct pipe_buffer), GFP_KERNEL_ACCOUNT)
```

每个缓冲区数据都通过`pipe_buffer`进行管理，其中`page`成员是缓冲区数据对应的物理页，`offset`成员指向数据在页内的偏移地址，`len`成员记录着未被读取过的数据长度。

```
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

## 零复制技术

在Linux中数据的复制操作一般指的都是将内存区域A中是数据复制到内存区域B中，这样做会消耗CPU资源且占用内存带宽，为了减少不必要的内存消耗，Linux系统推出了零复制`Zero-Copy`的概念，旨在减少数据复制过程中产生的消耗。

零复制只是一种设想，凡是可以减少复制开销的都可以算作是零复制技术，零复制技术在不同场景下的具体实现有所差异。

下面会介绍文件访问情境下的零复制技术。

### 文件与零复制

用户态程序最常使用的访问文件方式就是缓冲区IO、文件映射、直连IO、直接访问四种方式，它们的区别在于访问的层级不同。

```
用户态程序 <-> 虚拟文件系统 <-> 页缓存 <-> 块IO层 <-> 磁盘文件
```

- 缓冲区IO：缓冲区IO与虚拟文件系统进行交互，通过`open`、`write`、`read`等系统调用，提交请求给对应的文件系统，文件系统中的接口会将数据更新到页缓存内，或者从页缓存内获取数据，页缓存中的数据需要与磁盘文件进行同步。

- 页缓存：从缓冲区IO的描述中，可以知道页缓存是缓冲区IO的一部分。在这里我们要清楚一件事情，就是CPU对不同外设的访问速度，第一快是CPU内部的寄存器和缓存，第二快的内存，最慢的就是磁盘文件。如果程序的每一个读写操作都直接作用在磁盘文件上，就会导致CPU以较慢的速度读取或写入数据，为了缓解这一问题，Linux内核将用户态程序对文件中数据的访问移动到内存中进行，加快访问速度，然后定期更新到磁盘文件内，减少CPU访问磁盘的次数。

- 文件映射：文件映射会将磁盘文件映射到物理页上，用户态程序可以直接操作页缓存对磁盘文件中的数据进行读取或修改。

- 直连IO：页缓存通过块IO层与磁盘文件进行交互，而直连IO的意思就是直连块IO层，直接向磁盘文件读写数据。

- 直接访问：直接访问指的是用户态程序与存储设备间直接进行数据交互。

在一般情况下，用户态程序会通过`open`、`write`、`read`等方式进行缓冲区IO操作，在这种机制下，一段数据的写入需要经过4步，第一步是用户态程序中数据的本地存放（比如栈或堆），二是通过GLibC接口向内核发出写申请，三是内核申请物理页，四是内核向物理页中复制数据，在这个过程中需要消耗内核不小的精力，特别是操作量还不小的时候。

既然缓冲区IO的第一目的地都是物理内存页，先进行的也都是内存访问操作，那么有没有一种方案直接将文件放在内存上，然后用户态程序通过操作虚拟内存实现文件数据的读写呢？

当然可以，上方的文件映射就可以达到这一目的，因此文件映射就是一种零复制技术。

### 跨文件访问与零复制

对于多文件间数据交互的场景来讲，可以每个文件都映射一次，将对磁盘文件的操作转换为对内存的操作，最后由用户态程序通过`memcpy`完成数据的复制操作。

对于管道来讲不管是通过`iterate_and_advance`复制数据还是给管道缓冲区更新页信息，都不会使用`memcpy`这种易于产生开销的函数进行复制，为了提高跨文件间数据交互效，`splice`系统调用就此产生。

```
#define __NR_splice 275
```

这个系统调用的作用是实现文件与管道间的数据复制，将用户空间和内核空间的数据交互转变成内核空间内部的数据交换。

GLibC将它封装成了函数`splice`，调用者需要提供读取端和写入端文件。

```
ssize_t splice(int fd_in, off64_t *_Nullable off_in,
	int fd_out, off64_t *_Nullable off_out,
	size_t len, unsigned int flags);
```

`do_splice`函数会先通过`get_pipe_info`函数根据文件尝试获取`pipe`信息，当文件是管道时，`f_op`会被设置成`pipefifo_fops`，且管道文件创建时会通过`alloc_pipe_info`函数设置`private_data`元素，`get_pipe_info`函数也会先通过`f_op`和`private_data`辨别文件是不是管道成员，如果不是就返回空指针。

假如文件是管道文件，还会根据`for_splice`是否为真检查监视队列信息，如果启用了监视队列的功能那么`get_pipe_info`函数也会返回空指针，反之则正常返回。

当通知机制存在时，管道中的信息就不劳系统调用操心了。

```
splice
	-> __do_splice
		-> do_splice
			-> get_pipe_info
				-> struct pipe_inode_info *pipe = file->private_data
				-> if (file->f_op != &pipefifo_fops || !pipe)
					-> return NULL
				-> if (for_splice && pipe_has_watch_queue(pipe))
					-> return NULL
				-> return pipe
			-> splice_pipe_to_pipe
			-> do_splice_from
			-> splice_file_to_pipe
```

`do_splice`会使用`get_pipe_info`获取读写两端的信息，这时分成三种情况，一是两端都是管道，二是写入端是管道但读取端不是，三是读取端是管道但写入端不是。

#### 从管道读取数据写入到文件

先来看一下管道读取到文件的情况，它会通过文件系统指定的`splice_write`进行写操作。

```
if (ipipe)
	-> do_splice_from
		-> out->f_op->splice_write
```

`splice_write`成员一般对应着`iter_file_splice_write`。

`iter_file_splice_write`函数会先根据待写入数据长度`sd.total_len`陷入循环中。

进入循环后先通过`splice_from_pipe_next`函数获取数据，`splice_from_pipe_next`函数内部只要管道队列是空的就会一直陷在循环内，返回非零值代表正确获取到数据。

获取到数据后，会进入`for`循环向数组`array`内添加待写入数据信息。

构建好数据数组后，通过`iov_iter_bvec`函数将数组变成IO向量`iov IO Vector`信息，然后通过`vfs_iter_write`函数写入到文件内，`vfs_iter_write`函数最终会借助文件系统的`write_iter`接口写入到页缓存内（`write_iter`接口在上方分析过，只不过这里使用的是实际文件的文件系统接口，而不`pipefs`文件系统的接口）。

最后进入`while`循环内部，清空已经写入的管道数据。

```
iter_file_splice_write
	-> int nbufs = pipe->max_usage
	-> struct bio_vec *array = kcalloc(nbufs, sizeof(struct bio_vec), GFP_KERNEL)
	-> while (sd.total_len)
		-> splice_from_pipe_next
			-> while (pipe_empty(pipe->head, pipe->tail))
		-> if (ret <= 0)
			-> break
		-> left = sd.total_len
		-> for
			-> struct pipe_buffer *buf = &pipe->bufs[tail & mask]
			-> size_t this_len = buf->len
			-> this_len = min(this_len, left)
			-> array[n].bv_page = buf->page
			-> array[n].bv_len = this_len
			-> array[n].bv_offset = buf->offset
			-> left -= this_len
		-> iov_iter_bvec
		-> vfs_iter_write
			-> do_iter_write
				-> do_iter_readv_writev
					-> call_write_iter
						-> file->f_op->write_iter
		-> while
```

对于ext4文件来讲，`write_iter`接口最终会调用`iterate_and_advance`函数进行复制。

```
ext4_file_write_iter
	-> ext4_buffered_write_iter
		-> generic_perform_write
			-> copy_page_from_iter_atomic
				-> iterate_and_advance
```

#### 从文件读取数据写入到管道

再来看一下管道读取到文件的情况，它会通过文件系统指定的`splice_write`进行写操作。

```
splice_file_to_pipe
	-> do_splice_to
		-> in->f_op->splice_read
```

`splice_read`成员一般对应着`generic_file_splice_read`。

`generic_file_splice_read`函数会先调用`iov_iter_pipe`将标志位设置成`ITER_PIPE`，通过通过文件系统的`read_iter`接口从文件中读取数据到管道内（`read_iter`接口在上方分析过，只不过这里使用的是实际文件的文件系统接口，而不`pipefs`文件系统的接口）。

```
generic_file_splice_read
	-> iov_iter_pipe
	-> call_read_iter
		-> file->f_op->read_iter
```

对于ext4文件系统来讲，读取操作最终会落实到`filemap_read`，该函数会先通过`filemap_get_pages`获取页缓存，然后将页缓存交给`copy_page_to_iter`读取。

```
ext4_file_read_iter
	-> generic_file_read_iter
		-> filemap_read
			-> filemap_get_pages
			-> copy_folio_to_iter
				-> copy_page_to_iter
```

由于`ITER_PIPE`标志已经存在，所以`copy_page_to_iter`函数会调用`copy_page_to_iter_pipe`将文件对应页缓存上的数据复制到管道内，这里的复制数据操作上面提到过，它会直接让管道的缓冲区数据复用文件的页缓存，从而不产生复制操作。

```
copy_page_to_iter
	-> iov_iter_is_pipe
			-> copy_page_to_iter_pipe
```

#### 从管道读取到管道

最后一种情况就是管道读取到管道，这种情况下数据的复制操作会简单些，它会不管从输入端和输出端获取缓冲区数据，然后将输入端数据交换到输出端实现数据的复制。

复制操作只在管道文件写入到文件`fd_b`时发生一次，文件`fa_b`读取到管道文件时不会产生复制操作，从管道的读取端。

```
splice_pipe_to_pipe
	-> while
		-> ibuf = &ipipe->bufs[i_tail & i_mask]
		-> obuf = &opipe->bufs[o_head & o_mask]
		-> *obuf = *ibuf
```

### splice的示例

`splice`在Linux用户态程序的基本使用如下所示，它通过管道将文件`fd_a`中的内容复制到文件`fd_b`内，复制过程中只发生两次系统调用。

```
int pipe_fd[2]， fd_a, fd_b;

pipe(pipe_fd);

splice(fd_a, NULL, pipefd[1], NULL, 4096, SPLICE_F_MOVE|SPLICE_F_MORE);
splice(pipefd[0], NULL, fd_b, NULL, 4096, SPLICE_F_MOVE|SPLICE_F_MORE);
```

### PIPE_BUF_FLAG_CAN_MERGE标志

在使用`splice`时进行读写时，管道缓冲区会指向数据的所在物理页，而不发生复制行为。这个页不管是外来的还是自造的，只要有`PIPE_BUF_FLAG_CAN_MERGE`标志就是允许写入的。

```
pipe_wirte
	-> if (buf->flags & PIPE_BUF_FLAG_CAN_MERGE)
		-> copy_page_from_iter
			-> iterate_and_advance
```

`PIPE_BUF_FLAG_CAN_MERGE`标志的设置逻辑是是否使用直连IO读写数据。

当`pipe_write`向管道写入数据时，如果发现文件不会通过直连IO的方式进行读写（通过`O_DIRECT`标志位辨别），那么就会给管道缓冲区打上`PIPE_BUF_FLAG_CAN_MERGE`的标签。

```
is_packetized
	-> return (file->f_flags & O_DIRECT) != 0;

if (is_packetized(filp))
	buf->flags = PIPE_BUF_FLAG_PACKET;
else
	buf->flags = PIPE_BUF_FLAG_CAN_MERGE;
```

只要管道缓冲区中的`PIPE_BUF_FLAG_CAN_MERGE`标志位一天未被清除，内核都会认为管道缓冲区指向的页是可以写的。

## 漏洞为何产生？

从目前的状况来看，`PIPE_BUF_FLAG_CAN_MERGE`标志位的存在很可能就是漏洞产生的根源所在，这个标志位在内核中并不是一直存在的，下方的提交编号展示了该标志位引入的时间，以及引入的原因。

```
commit：f6dd975583bd8ce088400648fd9819e4691c8958
```

通过浏览提交说明以及代码内容，我们可以知道，管道向已有页内合并数据是早就存在的操作，只不过它不是通过`PIPE_BUF_FLAG_CAN_MERGE`标志位进行判断，而是将合并操作`anon_pipe_buf_ops`和不可合并操作`anon_pipe_buf_nomerge_ops`的实现区分开，只要`pipe_buf_can_merge`函数发现`ops`对应`anon_pipe_buf_ops`就代表可以合并，但如果是对应`anon_pipe_buf_nomerge_ops`，那就代表不能合并了。

```
pipe.c：

pipe_buf_mark_unmergeable
	-> if (buf->ops == &anon_pipe_buf_ops)
		-> buf->ops = &anon_pipe_buf_nomerge_ops

pipe_buf_can_merge
	-> return buf->ops == &anon_pipe_buf_ops
```

该次提交修改的文件还有`splice.c`，从该文件中的改动可以看到，`pipe_buf_mark_unmergeable`操作本身已经存在，说明Linux内核开发者们并没有忽略数据向已有页合并带来的安全问题，同时也随着补丁取消`PIPE_BUF_FLAG_CAN_MERGE`标志位的操作，从这个角度上看，合并写的安全问题应该是不存在的啊！

```
splice.c：

- pipe_buf_mark_unmergeable(obuf);
+ obuf->flags &= ~PIPE_BUF_FLAG_CAN_MERGE;
```

### 被修复的漏洞

但是`Dirty Pipe`漏洞又是怎么出现的呢？

在当前内核中，`Dirty Pipe`漏洞是已经被修复的。

```
uname -r
6.1.0-28-amd64
```

漏洞的修复由两个部分组成。

它在`copy_page_to_iter_pipe`和`push_pipe`处添加了`flags = 0`的设置。

假如没有这个设置，又会变成什么情况呢？

```
commit：9d2231c5d74e13b2a0546fee6737ee4446017903

copy_page_to_iter_pipe
+ buf->flags = 0;

push_pipe
+ buf->flags = 0;
```

首先`copy_page_to_iter_pipe`和`push_pipe`函数是管道读取数据时使用的接口，`pipe_write`函数运行时会根据是否使用直连IO的方式写入文件来设置标志位，如果不是内核会将物理页空间利用到极致，这个时候会设置`PIPE_BUF_FLAG_CAN_MERGE`标志允许物理页中新旧数据合并。

虽然`splice.c`中消除了`PIPE_BUF_FLAG_CAN_MERGE`标志，但这是不够的，因为`pipe_read`读出数据时，旧数据的状态情况是全部情况的，但在添加`buf->flags = 0`之前，`flags`的标记是一直留下的，虽然页是变化的，但遗留下来的标志位产生了隐患，每个页都是需要合并的吗，这个问题的答案一定不是肯定的。

这个改动并没有这一保留下来，在下方编号的提交记录中，会发现`buf->flags = 0`语句已经被清除掉了。

```
commit：47b7fcae419dc940e3fb8e58088a5b80ad813bbf
```

本次提交有一个重要的改变就是添加了`push_anon`和`push_page`，这个函数的主要区别在于一个是先分配新物理页，在通过`pipe_buf`获取缓冲区数据信息并设置物理页，另一个则会直接复用旧的物理页。

```
iov_iter.c：
push_anon
	-> alloc_page
	-> pipe_buf
	->  *buf = (struct pipe_buffer) { ... }

push_page
	-> pipe_buf
	-> *buf = (struct pipe_buffer) { ... }
```

这项改动虽然移除了`buf->flags = 0`语句，但是缓冲区信息会通过`*buf = (struct pipe_buffer) { ... }`语句重新初始化，`struct pipe_buffer`中的`flags`成员并没有进行设置，所以`flags`成员会默认初始化为0，保持了缓冲区信息读取后清空的逻辑。

### 漏洞的产生

从上面我们可以看到，漏洞修复的方式是在管道数据被读取后将自身信息清空（最关键的就是`flags`），避免自身状态对后续数据产生影响。

在`PIPE_BUF_FLAG_CAN_MERGE`标志合并进Linux内核代码之前，内核通过`ops`接口指针判断会不会进行合并操作，一般来讲`pipe_wire`阶段默认会设置`ops`为`anon_pipe_buf_ops`（可以合并缓冲区数据）。

```
anon_pipe_buf_ops
anon_pipe_buf_nomerge_ops
packet_pipe_buf_ops
```

进行`splice`操作时，由于`splice`允许向将文件的物理页提供给管道，对于内核来讲它是不希望这些物理页被盗取的，所以会通过`pipe_buf_mark_unmergeable`来消除合并操作。

当从文件读取数据复制到管道时，会经过`copy_page_to_iter`函数，因为管道将标志设置成了`ITER_PIPE`，所以会进入`copy_page_to_iter_pipe`导致`ops`指针改变。

```
copy_page_to_iter
	-> copy_page_to_iter_pipe
		-> buf->ops = &page_cache_pipe_buf_ops
```

改变后的指针变成了`page_cache_pipe_buf_ops`，而不再是`anon_pipe_buf_ops`，使得`pipe_buf_can_merge`判断失败，所以内核不会进行合并操作。

当`PIPE_BUF_FLAG_CAN_MERGE`标志合并进Linux内核后，`ops`的操作不再变来变去，`pipe_buf_can_merge`的判断也失效了，按理说读取完后，`flags`应该清空的，但实际上却并没有这样做，遗留下来的`PIPE_BUF_FLAG_CAN_MERGE`标志如果被滥用，就会出现磁盘文件被非预期操作更改的情况。

### 不生效的拦路虎

`pipe_write`写文件时，会通过`iov_iter_is_pipe`判断检查类型是不是`ITER_PIPE`，如果是就会触发报警信息并返回。

显然一开始开发的内核程序员知道`splice`复用物理页的风险，所以在这里设置了检查，这个检查是一直存在的，但是它为什么没有起到拦截作用呢？

```
_copy_from_iter
	-> if iov_iter_is_pipe
		-> WARN_ON
		-> return
```

虽然经过`splice`后，管道缓冲区数据类型会被打上`ITER_PIPE`的标签，但是只要是通过`read`或`wrtie`等方式经过`vfs`接口读写文件的话，类型都会被设置成`ITER_UBUF`。

```
vfs_read
	-> new_sync_read
		-> iov_iter_ubuf
			-> .iter_type = ITER_UBUF
vfs_write
	-> new_sync_write
		-> iov_iter_ubuf
			-> .iter_type = ITER_UBUF
```

因此`write(p[1], data, data_size)`虽然写的是管道文件，但是数据还是被打上了`ITER_UBUF`的标志，导致`WARN_ON`不被触发。

### 物理页的写回问题

内核通过标记物理页为`dirty`脏页，来控制物理页回写到硬盘上，为了触发脏页的设置，我们可以通过访问文件操作达到这一目的。

回写到磁盘文件上之后，我们就可以看到修改的内容。

### 总结

在`PIPE_BUF_FLAG_CAN_MERGE`标志引入之前，`PIPE_BUF_FLAG_XX`已经出现，当然之前`PIPE_BUF_FLAG_XX`并没有导致安全问题，这是因为不同的标志管理的范围是不同的，只有`PIPE_BUF_FLAG_CAN_MERGE`标志会影响被复用页的可写状态。

而通过`ops`指针判断的方法，因为`splice`操作后及时的更新免去一劫。

`PIPE_BUF_FLAG_XX`的引入本意是让内核代码变得更加优雅，但却产生了安全问题，这是内核程序员们的疏忽吗？

首先需要明确一点，`splice`带来的安全问题一直是被内核程序员们注意到的问题，比如通过数据的`ITER_PIPE`标志，以及读写通过`iov_iter_is_pipe`进行的判断，如果是`ITER_PIPE`类型就会触发`WARN_ON`警告。

那么内核程序员们一开始就没有打算初始化`flags`，是现有的检查手段让他们相信不会除非安全问题，还是他们真的忽略了呢？

不管如何，`PIPE_BUF_FLAG_CAN_MERGE`标志都被留存了下来，当检查条件与预期不匹配时漏洞就会产生，特别是错误的预期绕过的是权限相关检查的时候。

此时我们可以得到`Dirty Pipe`漏洞的利用流程。

```
1. 通过pipe_write写入数据，此时数据的buf->flags会默认加上PIPE_BUF_FLAG_CAN_MERGE标志
2. 因为默认可能会分配新页，所以通过pipe_read读取数据，将buf->page空出来
3. 通过splice将文件页缓存读取到管道内
4. 通过pipe_wrtie向管道写入数据，因为flags中的PIPE_BUF_FLAG_CAN_MERGE一直被保留了下来，所以pipe_wrtie会向文件页缓存内写入数据
```
