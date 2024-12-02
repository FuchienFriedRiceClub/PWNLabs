# 进程的贴身行囊 - 信号

信号是用户态进程与内核进行通信的一种方式，它是陷阱（软中断）的一种。如果想要查看所有的信号类型可以查询Linux手册。

信号抵达进行需要经过两个步骤，一是发送信号，而是接收信号。

## 信号与进程组

在Linux中进程的待处理的信号由`task_struct`结构体中的`signal`成员和`pending`成员进行记录,`signal`成员和`pending`成员的区别在于，`signal`成员中存放的待处理信号对整个进程组都是生效的，而`pending`成员只对指定的线程有效。

`signal`成员由`signal_struct`结构体定义，该结构体中的`shared_pending`成员是管理共享信号的主要成员，它由由`sigpending`结构体定义，`task_struct`结构体中的`pending`成员也由`sigpending`结构体定义。

```
struct signal_struct {
	refcount_t		sigcnt;
	......
	struct sigpending	shared_pending;
	......
	struct rw_semaphore exec_update_lock;
} __randomize_layout;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

struct taks_struct {
	......
	struct signal_struct			*signal;
	struct sighand_struct __rcu		*sighand;
	struct sigpending				pending;
	......
}
```

`sigpending`结构体中的`list`成员指向了待处理信号队列，从下面的定义中可以看到`info`记录了关键的信号信息。

`sigpending`结构体中还可以看到一个`list`成员的身影，既然`sigpending`结构体中的`list`成员已经可以管理待处理信号队列了，那么`sigpending`结构体中的`list`成员又有什么用呢？

```
#define __SIGINFO 			\
struct {				\
	int si_signo;			\
	int si_code;			\
	int si_errno;			\
	union __sifields _sifields;	\
}

typedef struct kernel_siginfo {
	__SIGINFO;
} kernel_siginfo_t;

struct sigqueue {
	struct list_head list;
	int flags;
	kernel_siginfo_t info;
	struct ucounts *ucounts;
};
```

要知道，在Linux中信号分成常规信号和实时信号，这里我们需要先了解一下它们的区别。

### 常规信号与实时信号

Linux中1号 - 31号是常规信号，32号+是实时信号。它们的区别在于，同进程下同类型的常规信号只能存在一个，当常规信号被响应后，下一个同类型的常规信号才可以进入队列。

对于实时信号来讲则不是这样，同进程下可以存在多个同类型的实时信号，系统会根据实时信号在队列中的数量进行多次响应。

因此`sigpending`结构体中的`list`成员管理着不同类型的信号，此链表中的信号类型是不能重复的，`sigpending`结构体中的`list`成员管理着同类型的信号，如果有需要且信号是实时信号，那么待处理信号就会被插入`sigpending`结构体中的`list`成员对应的队列中。

### 驱动验证

通过内核驱动（见附件）指定函数和进程ID，可以将进程尚未处理的信号信息打印出来，从下面可以看到，进程收到了信号`SIGTERM`，`SIGTERM`信号的序号是15，该信号是对整个进程组生效的。

```
arch_do_signal_or_restart

[16176.561445]  pending signal ->
[16176.561447]  shared pending signal ->
[16176.561448]          00000000 - signal num = 15 ;
```

## 信号的发送

信号发送的原因可以分成三种，一是内核检测到错误发送（比如段错误，但并不是所有的错误都会导致信号产生）进而向进程组发送信号，二是主动发送信号（比如调用`kill`函数、`alarm`函数或者使用`kill`程序），三是外部事件触发的信号（如I/O设备、其他进程）。

通过Shell运行的进程，通过键盘输入`CTRL + C`或`CTRL + Z`可以向进程发送`SIGINT`或`SIGTSTP`信号。

## 信号的接收

进程接收到信号后，会根据信号的类型执行默认的行为（终止进程、终止进程并转储、挂起、忽略信号）。

在C语言中允许程序通过`sigaction`函数（更加强大，`signal`函数是`sigaction`函数的子集）设置指定信号的处理方法，而不是按照默认行为处理。

```
void (*signal(int sig, void (*func)(int)))(int);

int sigaction(int signum,
	const struct sigaction *_Nullable restrict act,
	struct sigaction *_Nullable restrict oldact);

特殊的处理函数 ->
	SIG_DFL：执行默认操作
	SIG_IGN：忽略信号
```

C语言提供的信号处理函数并不是所有的信号都可以处理的，比如信号`SIGKILL`和`SIGSTOP`，它们就必须执行默认行为。

### 用户态程序查看信号的发出方

有时候程序接收到信号后，我们会想要知道信号发出方的信息，C语音允许程序员自定义信号处理函数。

自定义的信号处理函数会打印信号信息以及发送信息方的信息，发送方的信息被存储在`my_signal_handle`中的`siginfo`变量内。

运行拥有自定义的信号处理程序`SignalsHandleExample`后，向程序发送`SIGTERM`信号后，程序出现如下的打印，从打印中可以看到程序收到信号15（对应`SIGTERM`），`si_code`为0对应着`SI_USER`，代表信号由用户发出，`si_uid`给出了该用户的用户ID，`si_pid`给出了发出信号的进程ID。

通过`echo $$`可以将`kill`程序运行的进程ID打印出来，该进程ID是和`si_pid`一致的。

```
程序运行结果：
register signo 15 succeed
cannot register signo 9, errno 22
num 0 -> setjmp return: 0
enter setting4globaljmp
num 1 -> setjmp return: 2333
pid = 10411, waiting for a signal

[**] receive signal, signal base info:
signal num    = 15 
signal info   = 0x00007ffd67435e30
user context  = 0x00007ffd67435d00

[**] signinfo (signinfo_t size 0x80) - (_sifields size 0x70):
si_signo = 00000015 ; si_errno = 00000000 ; si_code = 00000000 ;
si_pid   = 00009013 ; si_uid   = 00001000 ;
[--] _sifields will be displayed differently depending on the signal
[--] only pid and uid will be shown here

[**] ucontext (ucontext_t size 0x3c8):
uc_flags = 0x0000000000000006 ; uc_link = 0x0000000000000000 ;
uc_stack (stack_t size 0x18) ->
        ss_sp = 0x0000000000000000 ; ss_flags = 0x0000000000000000 ; ss_size = 0x0000000000000000
uc_mcontext (mcontext_t size 0x100) ->
        ---- gregs start ----
        0x0000000000000000 ; 0x0000000000000064 ; 0x00007ffd67436053 ; 0x0000000000000202 ; 
        0x0000000000000000 ; 0x00007ffd674362a8 ; 0x0000000000403d78 ; 0x00007f8de3eec020 ; 
        0x00007ffd67435c20 ; 0x0000000001b612a0 ; 0x00007ffd67436180 ; 0x00007ffd67436298 ; 
        0x0000000000000000 ; 0xfffffffffffffffc ; 0x00007f8de3d93d10 ; 0x00007ffd67436178 ; 
        0x00007f8de3d93d10 ; 0x0000000000000202 ; 0x002b000000000033 ; 0x0000000000000000 ; 
        0x0000000000000000 ; 0x0000000000000000 ; 0x0000000000000000 ; 
        ---- gregs end ----
        ---- fpregs start -----
        cwd = 895 ; swd = 0 ; ftw = 0 ; fop = 0 ;
        rip = 0x0000000000000000 ; rdp = 0x0000000000000000 ;
        mxcsr = 0x00001f80 ; mxcr_mask = 0x0002ffff ;
        no [_st] [_xmm]
        ---- fpregs end ----
no uc_sigmask (sigset_t size 0x80)
__fpregs_mem (_libc_fpstate size 0x200) ->
        cwd = 0 ; swd = 0 ; ftw = 0 ; fop = 0 ;
        rip = 0x0000000000000000 ; rdp = 0x0000000000000000 ;
        mxcsr = 0x0000037f ; mxcr_mask = 0x00000000 ;
        no [_st] [_xmm]
__ssp (array size 0x20) ->
        0x0000000000000000 ; 0x0000000000000000 ; 0x0000000000000000 ; 0x00007ffd67436160 ; 
enter my_atexit_func, program will exit

主动触发程序信息：
kill -s SIGTERM 10411
echo $$
9013
```

当然这种方法仍然是不能处理某些信号的（如`SIGKILL`、`SIGSTOP`等等）。

## 信号的处理流程

### 谁来接收信号？

此处以`kill`程序为例，我们通过strace工具追踪该程序产生的系统调用。

```
strace /usr/bin/kill -s SIGTERM 2790
	execve("/usr/bin/kill", ["/usr/bin/kill", "-s", "SIGTERM", "2790"], 0x7ffc5e9561a8 /* 31 vars */) = 0
	......
	kill(2790, SIGTERM)
	exit_group(0)                           = ?
	+++ exited with 0 +++
```

在打印的内容中可以看到，`kill`程序通过`kill`函数向内核发出`__NR_kill`系统调用。

```
#define __NR_kill 62
```

内核会通过`SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)`对`__NR_kill`系统调用进行接收，其中的`kill_something_info`函数是实际处理的信号的地方。

```
SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
{
	struct kernel_siginfo info;

	prepare_kill_siginfo(sig, &info);

	return kill_something_info(sig, &info, pid);
}
```

从`kill_something_info`函数中不难看出，函数由三个部分组成，它们分别是`pid > 0`、`pid = -1`、`pid < 0`。，当`pid > 0`时，发送信号给指定的进程，当`pid = -1`时，发送信号给自身外的其余进程，当`pid < 0`时，发送信号给自身作者的进程组。

这里我们重点关注`pid > 0`的情况。

```
static int kill_something_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	int ret;

	if (pid > 0)
		return kill_proc_info(sig, info, pid);

	/* -INT_MIN is undefined.  Exclude this case to avoid a UBSAN warning */
	if (pid == INT_MIN)
		return -ESRCH;

	read_lock(&tasklist_lock);
	if (pid != -1) {
		......
	} else {
		......
	}
	read_unlock(&tasklist_lock);

	return ret;
}
```

`kill_proc_info`函数最终会调用`__send_signal_locked`函数对信号进行处理。

在`__send_signal_locked`函数的内部，首先会根据`type`变量判断是添加到给进程组还是线程（是`PIDTYPE_PID`时添加到线程队列），再通过`__sigqueue_alloc`分配一个`sigqueue`，然后`sigqueue`通过`list_add_tail`接口添加到`task_strut`中`pending`成员的链表内，作为待处理信号，最后将信号信息和发送方信息添加到`sigqueue`内。

```
kill_proc_info
	->	kill_pid_info
		->	group_send_sig_info
			->	do_send_sig_info
				-> send_signal_locked
					-> __send_signal_locked

enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_TGID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX,
};

static int __send_signal_locked(int sig, struct kernel_siginfo *info,
				struct task_struct *t, enum pid_type type, bool force)
{
	......
	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
	......
	q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit, 0);
	......
	if (q) {
		list_add_tail(&q->list, &pending->list);
		switch ((unsigned long) info) {
		case (unsigned long) SEND_SIG_NOINFO:
		clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = task_tgid_nr_ns(current,
							task_active_pid_ns(t));
			rcu_read_lock();
			q->info.si_uid =
				from_kuid_munged(task_cred_xxx(t, user_ns),
						 current_uid());
			rcu_read_unlock();
			break;
		......
		}
	}
	......
	complete_signal(sig, t, type);
	......
}
```

`complete_signal`函数会决定由信号由谁接收。首先判断的条件是`wants_signal`函数，在当前任务应该接收信号时，会将接收权限交给当前进程，之后如果发现信号是发送给指定线程或单线程进程的话，就会直接返回，最后会从多线程中找到一个可用的线程。

接下来如果发现发现信号是致命的，就会通过`signal_wake_up`接口给每一个线程都添加上`TIF_SIGPENDING`标志，反之则只给指定的线程添加`TIF_SIGPENDING`标志。

`TIF_SIGPENDING`标志代表存在待处理的信号。

```
signal_wake_up
	-> signal_wake_up_state
		-> set_tsk_thread_flag: TIF_SIGPENDING

static void complete_signal(int sig, struct task_struct *p, enum pid_type type)
{
	struct signal_struct *signal = p->signal;
	struct task_struct *t;

	if (wants_signal(sig, p))
		t = p;
	else if ((type == PIDTYPE_PID) || thread_group_empty(p))
		return;
	else {
		......
	}
	if (sig_fatal(p, sig) &&
	    (signal->core_state || !(signal->flags & SIGNAL_GROUP_EXIT)) &&
	    !sigismember(&t->real_blocked, sig) &&
	    (sig == SIGKILL || !p->ptrace)) {
		......
		do {
			task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
			sigaddset(&t->pending.signal, SIGKILL);
			signal_wake_up(t, 1);
		} while_each_thread(p, t);
		......
	}
	signal_wake_up(t, sig == SIGKILL);
	return;
}
```

### 何时处理信号？

不管出于哪种原因发送信号，它们第一个需要的抵达的目标地点都是相同的，这个目标地点就是内核，那么内核又是如何进一步处理信号的呢？

对于内核而言，它会通过`do_signal`函数（它是架构指定的，具体名字可能不同）处理信号，下面通过`kprobe`机制中的`pre_handler`在`arch_do_signal_or_restart`函数之前打印出栈回溯（详情可见驱动代码）。

从栈回溯中可以看到，此时用户空间触发系统调用进入内核空间，当`do_syscall_64`函数执行完系统调用后，会调用`syscall_exit_to_user_mode`函数从内核空间退回到用户空间，使用`arch_do_signal_or_restart`函数处理信号的操作也发生在这一阶段。

```
CPU: 4 PID: 5738 Comm: srop_example
Call Trace:
<TASK>
dump_stack_lvl+0x44/0x5c
? arch_do_signal_or_restart+0x1/0x830
stack_dump_by_kprobe_pre+0x3b/0x40 [lde]
kprobe_ftrace_handler+0x10b/0x1b0
0xffffffffc02b90c8
? arch_do_signal_or_restart+0x1/0x830
arch_do_signal_or_restart+0x5/0x830
exit_to_user_mode_prepare+0x195/0x1e0
syscall_exit_to_user_mode+0x17/0x40
do_syscall_64+0x61/0xb0
......
entry_SYSCALL_64_after_hwframe+0x6e/0xd8
```

`exit_to_user_mode_loop`函数会接收`ti_work`参数，该参数调用`read_thread_flags`接口，该接口会从`thread_info`结构体内读出`flags`成员，接收`ti_work`参数后，会检查`TIF_SIGPENDING`标志位（上面说过，待处理信号会添加该标志位），如果发现`TIF_SIGPENDING`标志位存在，就说明存在待处理信号此时就会调用`arch_do_signal_or_restart`函数。

```
syscall_exit_to_user_mode
	-> __syscall_exit_to_user_mode_work
		-> exit_to_user_mode_prepare
			-> exit_to_user_mode_loop
				-> arch_do_signal_or_restart

ti_work = read_thread_flags();
static unsigned long exit_to_user_mode_loop(struct pt_regs *regs,
					    unsigned long ti_work)
{
	......
	if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
			arch_do_signal_or_restart(regs);
	......
}
```

### 如何处理信号？

`arch_do_signal_or_restart`函数响应的操作分成两部分，一是通过`get_signal`函数获取信号信息，二是通过`handle_signal`函数处理信号。

```
struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};
struct pt_regs *regs
struct ksignal ksig

arch_do_signal_or_restart
	-> get_signal(&ksig)
		-> handle_signal(&ksig, regs)
```

`handle_signal`函数首先会通过`test_thread_flag`函数检查`TIF_SINGLESTEP`标志位，该标志位用于标记程序是否被中断下来，如果标志位存在，那就会通过`user_disable_single_step`函数将`TIF_SINGLESTEP`标志位清除掉，并通知调试器。

当调试器挂载到程序后，再触发信号时，会发现调试器会先收到通知，之后才是信号处理函数，原因就在这里。

```
static void
handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	bool stepping, failed;
	struct fpu *fpu = &current->thread.fpu;

	......

	stepping = test_thread_flag(TIF_SINGLESTEP);
	if (stepping)
		user_disable_single_step(current);

	failed = (setup_rt_frame(ksig, regs) < 0);
	if (!failed) {
		regs->flags &= ~(X86_EFLAGS_DF|X86_EFLAGS_RF|X86_EFLAGS_TF);
		fpu__clear_user_states(fpu);
	}
	signal_setup_done(failed, ksig, stepping);
}
```

`setup_rt_frame`函数是一个关键操作，第一步通过`get_sigframe`获取一个新的栈帧。

```
static int __setup_rt_frame(int sig, struct ksignal *ksig, sigset_t *set, struct pt_regs *regs)
{
	struct rt_sigframe __user *frame;
	void __user *fp = NULL;
	unsigned long uc_flags;

	if (!(ksig->ka.sa.sa_flags & SA_RESTORER))
		return -EFAULT;

	frame = get_sigframe(&ksig->ka, regs, sizeof(struct rt_sigframe), &fp);
	uc_flags = frame_uc_flags(regs);

	if (!user_access_begin(frame, sizeof(*frame)))
		return -EFAULT;

	unsafe_put_user(uc_flags, &frame->uc.uc_flags, Efault);
	unsafe_put_user(0, &frame->uc.uc_link, Efault);
	unsafe_save_altstack(&frame->uc.uc_stack, regs->sp, Efault);

	unsafe_put_user(ksig->ka.sa.sa_restorer, &frame->pretcode, Efault);
	unsafe_put_sigcontext(&frame->uc.uc_mcontext, fp, regs, set, Efault);
	unsafe_put_sigmask(set, frame, Efault);
	user_access_end();

	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		if (copy_siginfo_to_user(&frame->info, &ksig->info))
			return -EFAULT;
	}

	regs->di = sig;
	regs->ax = 0;
	regs->si = (unsigned long)&frame->info;
	regs->dx = (unsigned long)&frame->uc;
	regs->ip = (unsigned long) ksig->ka.sa.sa_handler;
	regs->sp = (unsigned long)frame;
	regs->cs = __USER_CS;

	if (unlikely(regs->ss != __USER_DS))
		force_valid_ss(regs);

	return 0;

Efault:
	user_access_end();
	return -EFAULT;
}

setup_rt_frame
	-> __setup_rt_frame
```

新的栈帧通过`rt_sigframe`结构体描述，其中`pretcode`代表着信号处理完成后下一步的返回地址，`uc`记录了上下文信息，`info`记录了信号信息。

```
struct rt_sigframe {
	char __user *pretcode;
	struct ucontext uc;
	struct siginfo info;
};
```

通过`user_access_end`结束之前的操作，可以将原始的上下文信息保存在用户态程序的栈上。

完成栈上数据的设置操作后，会继续更新用户态程序的寄存器信息，其中当前程序指针寄存器被放置了信号处理函数的地址。

```
copy_siginfo_to_user会往ucontext_t涵盖的范围内进行复制

sp + 0x0	| sigreturn			|
sp + 0x8	| ucontext_t* start	|
sp + 0x3D0	| ucontext_t* end	|

(gdb) p /x *(ucontext_t*)$rdx
$2 = {uc_flags = 0x6, uc_link = 0x0, uc_stack = {ss_sp = 0x0, ss_flags = 0x2, 
    ss_size = 0x0}, uc_mcontext = {gregs = {0x0, 0x64, 0x7fffffffddc4, 0x202, 0x0, 
      0x7fffffffe018, 0x403d78, 0x7ffff7ffd020, 0x7fffffffd990, 0x4052a0, 
      0x7fffffffdef0, 0x7fffffffe008, 0x0, 0xfffffffffffffffc, 0x7ffff7e9ed10, 
      0x7fffffffdee8, 0x7ffff7e9ed10, 0x202, 0x2b000000000033, 0x0, 0x1, 0x0, 0x0}, 
    fpregs = 0x7fffffffdc40, __reserved1 = {0xc157, 0x7ffff7fc36b0, 0x3, 
      0x7fff00000000, 0xffe2e0, 0x7ffff7ffe668, 0x7ffff7fcb000, 0x7ffff7fcbb82}}, 
  uc_sigmask = {__val = {0x0, 0xf, 0x0, 0x3e800000d81, 0x0 <repeats 12 times>}}, 
  __fpregs_mem = {cwd = 0x0, swd = 0x0, ftw = 0x0, fop = 0x0, rip = 0x0, rdp = 0x0, 
    mxcsr = 0x37f, mxcr_mask = 0x0, _st = {{significand = {0x0, 0x0, 0x0, 0x0}, 
        exponent = 0x0, __glibc_reserved1 = {0x0, 0x0, 0x0}}, {significand = {
          0x1f80, 0x0, 0xffff, 0x2}, exponent = 0x0, __glibc_reserved1 = {0x0, 0x0, 
          0x0}}, {significand = {0x0, 0x0, 0x0, 0x0}, exponent = 0x0, 
        __glibc_reserved1 = {0x0, 0x0, 0x0}}, {significand = {0x0, 0x0, 0x0, 0x0}, 
        exponent = 0x0, __glibc_reserved1 = {0x0, 0x0, 0x0}}, {significand = {0x0, 
          0x0, 0x0, 0x0}, exponent = 0x0, __glibc_reserved1 = {0x0, 0x0, 0x0}}, {
        significand = {0x0, 0x0, 0x0, 0x0}, exponent = 0x0, __glibc_reserved1 = {
          0x0, 0x0, 0x0}}, {significand = {0x0, 0x0, 0x0, 0x0}, exponent = 0x0, 
        __glibc_reserved1 = {0x0, 0x0, 0x8000}}, {significand = {0x4007, 0x0, 0x0, 
          0x0}, exponent = 0x0, __glibc_reserved1 = {0x0, 0x0, 0x8000}}}, _xmm = {{
        element = {0x3fff, 0x0, 0x0, 0x80000000}}, {element = {0x3fff, 0x0, 
          0x4052a0, 0x0}}, {element = {0x4052a0, 0x0, 0x25252525, 0x25252525}}, {
        element = {0x25252525, 0x25252525, 0x0, 0xffffff00}}, {element = {0x0, 
          0xffffff00, 0x0, 0x0}}, {element = {0xffffff00, 0x0, 0x0, 0xffff0000}}, {
        element = {0x0, 0x0, 0x0, 0x0}}, {element = {0x0, 0x0, 0x0, 0x0}}, {
        element = {0x0, 0x0, 0x6620676e, 0x6120726f}}, {element = {0x67697320, 
          0xa6c616e, 0xff000000, 0x0}}, {element = {0x0, 0x0, 0x656c70, 
--Type <RET> for more, q to quit, c to continue without paging--
          0x4c454853}}, {element = {0x622f3d4c, 0x622f6e69, 0x0, 0x0}}, {element = {
          0x0, 0x0, 0x0, 0x0}}, {element = {0x0, 0x0, 0x0, 0x0}}, {element = {0x0, 
          0x0, 0x0, 0x0}}, {element = {0x0, 0x0, 0x0, 0x0}}}, __glibc_reserved1 = {
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xffffdef0, 0x7fff, 0x0, 0x0, 0xffffe018, 
      0x7fff, 0x403d78, 0x0, 0xf7ffd020, 0x7fff, 0xf7e1d65b, 0x7fff, 0x46505853, 
      0x204, 0x0, 0x0, 0x200, 0x0}}, __ssp = {0x0, 0x0, 0x0, 0x0}}
```

### 进入信号处理函数

我们在`my_signal_handle`函数进行处理时将程序中断下来观察栈回溯。

```
(gdb) bt
#0  my_signal_handle (signum=15, si=0x7fffffffdbb0, ucontext=0x7fffffffda80)
    at main.c:152
#1  <signal handler called>
#2  0x00007ffff7e9ed10 in __libc_pause () at ../sysdeps/unix/sysv/linux/pause.c:29
#3  0x0000000000401789 in main () at main.c:241

#define __NR_rt_sigreturn 15

(gdb) frame 1
#1  <signal handler called>
(gdb) disassemble 
Dump of assembler code for function __restore_rt:
=> 0x00007ffff7e07050 <+0>:     mov    $0xf,%rax
   0x00007ffff7e07057 <+7>:     syscall
   0x00007ffff7e07059 <+9>:     nopl   0x0(%rax)
End of assembler dump.
```

1号栈帧被内核放置了信号处理结束后的操作`__restore_rt`函数，这个函数非常简单，它会将系统调用号放入`rax`寄存器内，然后执行系统调用，系统调用号15对应着`__NR_rt_sigreturn`。

```
(gdb) frame 1
#1  <signal handler called>
(gdb) disassemble 
Dump of assembler code for function __restore_rt:
=> 0x00007f2ddea2c050 <+0>:     mov    $0xf,%rax
   0x00007f2ddea2c057 <+7>:     syscall
   0x00007f2ddea2c059 <+9>:     nopl   0x0(%rax)
```

### 完成信号处理后会干什么？

当`__restore_rt`函数触发系统调用时就会再次陷入内核当中，内核根据系统调用`__NR_rt_sigreturn`会触发`__do_sys_rt_sigreturn`函数。

```
[10732.866379] CPU: 2 PID: 4567 Comm: srop_example Tainted: G           OE      6.1.0-25-amd64 #1  Debian 6.1.106-3
[10732.866382] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[10732.866384] Call Trace:
[10732.866387]  <TASK>
[10732.866390]  dump_stack_lvl+0x44/0x5c
[10732.866399]  stack_dump_by_kprobe_pre+0x5a/0xef0 [lde]
[10732.866406]  ? __do_sys_rt_sigreturn+0x1/0xf0
[10732.866411]  kprobe_ftrace_handler+0x10b/0x1b0
[10732.866420]  0xffffffffc034e0c8
[10732.866428]  ? __do_sys_rt_sigreturn+0x1/0xf0
[10732.866433]  __do_sys_rt_sigreturn+0x5/0xf0
[10732.866437]  do_syscall_64+0x55/0xb0
......
[10732.866503]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8
```

该函数操作并不复杂，主要就是还原之前保存在栈上的上下文信息。

```
SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe __user *frame;
	sigset_t set;
	unsigned long uc_flags;

	frame = (struct rt_sigframe __user *)(regs->sp - sizeof(long));
	if (!access_ok(frame, sizeof(*frame)))
		goto badframe;
	if (__get_user(*(__u64 *)&set, (__u64 __user *)&frame->uc.uc_sigmask))
		goto badframe;
	if (__get_user(uc_flags, &frame->uc.uc_flags))
		goto badframe;

	set_current_blocked(&set);

	if (!restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
		goto badframe;

	if (restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->ax;

badframe:
	signal_fault(regs, frame, "rt_sigreturn");
	return 0;
}
```

此时再次回到用户态程序后，程序就会接着执行处理信号前的内容。

# 利用思路

在整个信号处理的过程中，内核会将上下文信息保存在用户态程序的栈上，后续再通过`sigreturn`系统调用发出恢复信号，因为用户态栈是可读可写的，这非常方便我们进行控制，当我么规划好`sigreturn`所需要的栈数据并触发`sigreturn`系统调用时，就会让程序跳入我们的控制之内。

那么栈上的上下文信息应该如何构造呢？

被压入栈的上下文信息通过`ucontext_t`结构体进行描述，`ucontext_t`结构体中的`uc_mcontext`成员内的`gregs`记录着信号处理函数执行前的寄存器信息。

```
---- gregs start ----
0x0000000000000000 ; 0x0000000000000064 ; 0x00007fffffffddc4 ; 0x0000000000000202 ; 
0x0000000000000000 ; 0x00007fffffffe018 ; 0x0000000000403d78 ; 0x00007ffff7ffd020 ; 
0x00007fffffffd990 ; 0x00000000004052a0 ; 0x00007fffffffdef0 ; 0x00007fffffffe008 ; 
0x0000000000000000 ; 0xfffffffffffffffc ; 0x00007ffff7e9ed10 ; 0x00007fffffffdee8 ; 
0x00007ffff7e9ed10 ; 0x0000000000000202 ; 0x002b000000000033 ; 0x0000000000000000 ; 
0x0000000000000001 ; 0x0000000000000000 ; 0x0000000000000000 ;
---- gregs end ----

(gdb) info registers 
rax            0xfffffffffffffdfe  -514
rbx            0x7fffffffe008      140737488347144
rcx            0x7ffff7e9ed10      140737352690960
rdx            0x0                 0
rsi            0x4052a0            4215456
rdi            0x7fffffffd990      140737488345488
rbp            0x7fffffffdef0      0x7fffffffdef0
rsp            0x7fffffffdee8      0x7fffffffdee8
r8             0x0                 0
r9             0x64                100
r10            0x7fffffffddc4      140737488346564
r11            0x202               514
r12            0x0                 0
r13            0x7fffffffe018      140737488347160
r14            0x403d78            4210040
r15            0x7ffff7ffd020      140737354125344
rip            0x7ffff7e9ed10      0x7ffff7e9ed10 <__libc_pause+16>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

`gregs`中共包含23个寄存器，下面列出了元素0到元素22对应的寄存器名。

```
r8      r9      r10          r11
r12     r13     r14          r15
rdi     rsi     rbp          rbx
rdx     rax     rcx          rsp
rip     eflags  cs|gs|fs|ss  err
trapno  oldmask cr2
```

显然当我们控制`rip`寄存器及传递形参的`rdi`等寄存器中数值时，就可以借助`sigreturn`的返回操作跳转到我们期望中的位置，除此之外`rsp`寄存器也位于栈上，当通过`pop rip`（如`ret`）操作获取下一条程序指针时，我们就可以通过控制`rsp`组成利用链。

# 示例讲解

程序的源代码和编译命令在下方给出了。

```
编译命令：
as -o test.o main.S
ld -s -o test test.o

源代码：
.text
.global _start

_start:
	xor %rax,%rax
	mov $0x400,%edx
	mov %rsp,%rsi
	mov %rax,%rdi
	syscall
	ret
```

程序并不复杂，为了基于信号返回机制完成ROP，我们这里第一步需要构造`sigreturn`需要的栈，在`pwntool`中的`SigreturnFrame`接口可以直接创造一个假的栈，然后再对里面的数据进行修改。

当我们想要通过`execive`创建进程时，首先需要考虑的就是参数问题，由于我们需要给寄存器明确指示参数的所在位置，因此我们需要知道一个栈上的地址，并利用它作为基地址填充数据。

这个程序非常简单，因此原始的栈上只包含`argc`、`argv`、环境变量以及`auxv`，从`argv`开始任意的地址都是栈上的地址，程序读取0x400，如果我们可以越过首条指令，让`rax`为1，那么就可以泄露`rsp+0x0`到`rsp+0x400`范围内的数据，并轻松的得到一个栈上的地址。

`rax`寄存器非常好控制，它有一个特殊用途，就是保存返回值，如果我们只读取一个字节，并让程序在结束后从`mov $0x400,%edx`继续运行，就可以控制`rax`寄存器，新发送的一个字节会覆盖`rsp+0x0`数据的最低位字节，当`rsp+0x0`处原本就存储着一个程序地址，我们再发送`mov $0x400,%edx`对应的最低字节数据，就可以跳过`xor`指令。

## 开启调试模式才能PWN？

在运行调试脚本的时候发现只有打开`pwntool`的调试开关后，才可以正常的完成PWN，否则就会失败。

```
log_level = 'debug'
```

失败之前会先进入交互模式，此时不管你输入什么都会立即失败，比如这里我们直接输入了回车键，然后直接收到了`SIGSEGV`的崩溃错误。

```
[*] Switching to interactive mode
$

Program received signal SIGSEGV, Segmentation fault.
```

观察`rsp`上的数据可以发现回车键对应的ASCII码`0x0a`被送进了缓冲区当中。

```
(gdb) x /gx $rsp
0x7fff397d9998: 0x424242424242420a
```

程序仍然在读取信息，这与我们进入交互模式时是与Shell进行交互的初衷有所背离。

显然有部分的信息没有发送给程序。

要知道这是一段极其简单的汇编代码，并且直接通过`syscall`调用的`read`接口，并没有给`stdout`等文件处理缓冲区，由于脚本发送数据的速度过快，同时又没有缓冲区进行临时的存在，导致了数据的丢失，因为开启调试模式后，调试信息的输出需要占用一定的时间，所以`send`会间隔一段时间后再发送，就不会产生数据丢失的情况。

我们在`send`之后添加`sleep`函数，也可也缓解这一问题。

```
import time

time.sleep(1)
```
