
# 快速系统调用的解密

前面在解析IDT表中陷阱初始化时，发现该表只会处理`int 0x80`软中断发起的系统调用，而直接通过x86_64指令集中系统调用指令发起的系统调用则会交给MSR寄存器中的`STAR`和`LSTAR`进行处理，这两个寄存器会保存对应的系统调用处理函数地址。

在Linux内核的早期，由于x86指令集并没有专门的指令处理系统调用，所以Linux内核通过`int 0x80`来触发软中断，随着时间的推移x86_64指令集提供了专门的系统调用指令，但是不同的处理器实现是不一样的，对于用户态程序来讲，它有天然的理由不去理会这些问题，“都是内核和处理器的原因啊，为什么要我管”，处理器当然也是一副硬姿态，反正我就这样实现了，内核你看着办吧！

因此没有办法的内核，只能担负起处理这个“脏”任务的责任，内核的处理方式是这样的：在启动阶段根据具体处理器加载不同的系统调用处理镜像，程序发起系统调用时会将执行权限交给系统调用处理镜像，而不需要考虑具体的实现。

## 内核支持 - VSyscall

VSyscall的初始化是在内核启动阶段进行的，它由著名`start_kernel`启动函数发起指定架构的初始化操作`setup_arch`，在`setup_arch`函数的内部会针对系统调用映射内存页，提供给用户态程序使用。

```
asmlinkage __visible __init __no_sanitize_address __noreturn __no_stack_protector
void start_kernel(void)
{
	......
	setup_arch(&command_line);
	......
}

void __init setup_arch(char **cmdline_p)
{
	......
	map_vsyscall();
	......
}
```

VSyscall依赖编译选项`CONFIG_X86_VSYSCALL_EMULATION`，只有当它开启时，VSyscall的功能才会被启用。

```
#ifdef CONFIG_X86_VSYSCALL_EMULATION
extern void map_vsyscall(void);
extern void set_vsyscall_pgtable_user_bits(pgd_t *root);

/*
 * Called on instruction fetch fault in vsyscall page.
 * Returns true if handled.
 */
extern bool emulate_vsyscall(unsigned long error_code,
			     struct pt_regs *regs, unsigned long address);
#else
static inline void map_vsyscall(void) {}
static inline bool emulate_vsyscall(unsigned long error_code,
				    struct pt_regs *regs, unsigned long address)
{
	return false;
}
#endif
```

当`map_vsyscall`函数开始时，它会先进行一个很重要的操作，就是获取VSyscall所在内存页的物理地址。

```
void __init map_vsyscall(void)
{
	extern char __vsyscall_page;
	unsigned long physaddr_vsyscall = __pa_symbol(&__vsyscall_page);

	/*
	 * For full emulation, the page needs to exist for real.  In
	 * execute-only mode, there is no PTE at all backing the vsyscall
	 * page.
	 */
	if (vsyscall_mode == EMULATE) {
		__set_fixmap(VSYSCALL_PAGE, physaddr_vsyscall,
			     PAGE_KERNEL_VVAR);
		set_vsyscall_pgtable_user_bits(swapper_pg_dir);
	}

	if (vsyscall_mode == XONLY)
		vm_flags_init(&gate_vma, VM_EXEC);

	BUILD_BUG_ON((unsigned long)__fix_to_virt(VSYSCALL_PAGE) !=
		     (unsigned long)VSYSCALL_ADDR);
}
```

`__pa_symbol`宏是Linux中较为常见的一种宏，它接收一个地址作为参数，然后减去内核映射的基地址获取偏移值，最后加上物理地址的基地址，获取形参地址对应的物理地址。

根据`__START_KERNEL_map`可以知道内核映射的基地址是0xffffffff80000000。

```
#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif
#define __START_KERNEL_map	_AC(0xffffffff80000000, UL)

static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}

#define __phys_addr(x)		__phys_addr_nodebug(x)

#ifndef __pa
#define __pa(x)		__phys_addr((unsigned long)(x))
#endif
```

在获取`__vsyscall_page`的物理地址`physaddr_vsyscall`后，会对其所在内存页的属性进行设置，设置的依据是`vsyscall_mode`，它有两种设置方式，一是根据内核配置选项`CONFIG_LEGACY_VSYSCALL_XONLY`设定的默认值，二是根据内核命令行参数进行配置。

```
static enum { EMULATE, XONLY, NONE } vsyscall_mode __ro_after_init =
#ifdef CONFIG_LEGACY_VSYSCALL_NONE
	NONE;
#elif defined(CONFIG_LEGACY_VSYSCALL_XONLY)
	XONLY;
#else
	#error VSYSCALL config is broken
#endif

static int __init vsyscall_setup(char *str)
{
	if (str) {
		if (!strcmp("emulate", str))
			vsyscall_mode = EMULATE;
		else if (!strcmp("xonly", str))
			vsyscall_mode = XONLY;
		else if (!strcmp("none", str))
			vsyscall_mode = NONE;
		else
			return -EINVAL;

		return 0;
	}

	return -EINVAL;
}
early_param("vsyscall", vsyscall_setup);
```

### 启动参数

`early_param`宏会将名称及符号放入`.init.setup`节中，不同表项间通过拼接的符号`__setup_##unique_id`进行区分。

除了`early_param`宏外，`__setup`宏也会这样操作，`__setup`和`early_param`的归宿都是`__setup_param`宏，该宏声明的`.init.setup`节内元素会在内核初始化时进行使用。

```
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(".init.setup")				\
		__aligned(__alignof__(struct obs_kernel_param))		\
		= { __setup_str_##unique_id, fn, early }

#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)

#define early_param(str, fn)						\
	__setup_param(str, fn, fn, 1)
```

每个表项都会按照`obs_kernel_param`结构体的结构进行放置。

```
struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};
```

内核针对`__setup_param`进行初始化的地方分成两个部分，第一部分是`early_param`对应的`parse_early_param`函数，第二部分则是`after_dashes`对应`__setup`。

```
void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strscpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

asmlinkage __visible __init __no_sanitize_address __noreturn __no_stack_protector
void start_kernel(void)
{
	......
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	......
}
```

不管哪一个部分，最终的目标都是通过`parse_args`对命令行参数进行解析，然后根据指定的处理函数`parse_unknown_fn`（`parse_args`中最后一个参数）对参数的要求进行处理。

```
static int parse_one(char *param,
		     char *val,
		     const char *doing,
		     const struct kernel_param *params,
		     unsigned num_params,
		     s16 min_level,
		     s16 max_level,
		     void *arg, parse_unknown_fn handle_unknown)
{
	......
	if (handle_unknown) {
		pr_debug("doing %s: %s='%s'\n", doing, param, val);
		return handle_unknown(param, val, doing, arg);
	}
	......
}

char *parse_args(const char *doing,
		 char *args,
		 const struct kernel_param *params,
		 unsigned num,
		 s16 min_level,
		 s16 max_level,
		 void *arg, parse_unknown_fn unknown)
{
	......
	ret = parse_one(param, val, doing, params, num,
				min_level, max_level, arg, unknown);
	......
}
```

`__setup`和`early_param`的区别在于，`early_param`用于解析静态命令行参数，`__setup`用于解析动态命令行参数。为了保障动态命令行参数设置的值是生效的，所以`__setup`对应的解析处理会晚于`early_param`宏。

静态命令行参数是内核编译时确定下来的，如ARM设备上DTS中的`chosen`节点中的`bootargs`项，以及x86_64设备上保存在BIOS内的参数`real_mod_date`（上电后先进入实模式）。而动态命令行参数指的则是启动引导程序传递给内核的参数，如UEFI中的GRUB配置文件，以及UBoot内向内核传递的参数。

除此之外，`__setup`和`early_param`另一个区别在于参数的预处理函数不同，`__setup`会把解析好的参数交给`unknown_bootoption`函数，而`early_param`则会交给`do_early_param`函数。

两个预处理函数最终都会将处理权限交给通过`__setup_param`宏指定的处理函数，且都是用`__setup_start`和`__setup_end`判断`.init.setup`节的区间，两者的主要区别在于`__setup_start`不会对`early`为真的参数进行处理，但`__setup_param`就会。

```
static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	......
	if (obsolete_checksetup(param))
		return 0;
	......
}

static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}
```

`__setup_start`和`__setup_end`会在vmlinux链接时产生，`vmlinux.lds.S`汇编代码会让它们标记`.init.setup`节的起始位置。

```
vmlinux.lds.S：
INIT_DATA_SECTION(16)

vmlinux.lds.h：
#define INIT_SETUP(initsetup_align)					\
		. = ALIGN(initsetup_align);				\
		BOUNDED_SECTION_POST_LABEL(.init.setup, __setup, _start, _end)
#define INIT_DATA_SECTION(initsetup_align)				\
	.init.data : AT(ADDR(.init.data) - LOAD_OFFSET) {		\
		INIT_DATA						\
		INIT_SETUP(initsetup_align)				\
		INIT_CALLS						\
		CON_INITCALL						\
		INIT_RAM_FS						\
	}

生成的vmlinux.lds：
.init.data : AT(ADDR(.init.data) - 0xffffffff80000000) {
	......
	__setup_start = .; KEEP(*(.init.setup)) __setup_end = .;
	......
}
```

从上面可以看到`.init.setup`被放置于`.init.data`节当中。

```
readelf -l  ./vmlinux：
Section to Segment mapping:
  Segment Sections...
   00     .text .rodata .pci_fixup .tracedata .printk_index __ksymtab __ksymtab_gpl __ksymtab_strings __init_rodata __param __modver __ex_table .notes .BTF .BTF_ids 
   01     .data __bug_table .orc_unwind_ip .orc_unwind .orc_lookup .vvar 
   02     .data..percpu 
   03     .init.text .altinstr_aux .init.data .x86_cpu_dev.init .parainstructions .retpoline_sites .return_sites .ibt_endbr_seal .altinstructions .altinstr_replacement .apicdrivers .exit.text .smp_locks .data_nosave .bss .brk .init.scratch 
   04     .notes
```

不过可惜的是，当Linux完成启动后`.init.xxx`节的信息就会被释放掉，因此内核当中写入`.init.xxx`中的信息都是无法在Linux运行阶段查看的。

```
#define __init		__section(".init.text") __cold  __latent_entropy __noinitretpoline
#define __initdata	__section(".init.data")
#define __initconst	__section(".init.rodata")
```

需要释放的内存区域会在`vmlinux.ld.S`内标记出来。

```
void mark_rodata_ro(void)
{
	......
	free_kernel_image_pages("unused kernel image (text/rodata gap)",
				(void *)text_end, (void *)rodata_start);
	free_kernel_image_pages("unused kernel image (rodata/data gap)",
				(void *)rodata_end, (void *)_sdata);
}

void __ref free_initmem(void)
{
	......
	free_kernel_image_pages("unused kernel image (initmem)",
				&__init_begin, &__init_end);
}

vmmlinux.ld.S：
/* Init code and data - will be freed after init */
	. = ALIGN(PAGE_SIZE);
	.init.begin : AT(ADDR(.init.begin) - LOAD_OFFSET) {
		__init_begin = .; /* paired with __init_end */
	}

.init.end : AT(ADDR(.init.end) - LOAD_OFFSET) {
		__init_end = .;
	}
```

### 内存页的设置

对于VSyscall来讲，模式不同对内存页设置的参数也会不同。

当模式为`EMULATE`时，会通过`__set_fixmap`将Vsyscall处理函数映射到指定的位置，`VSYSCALL_PAGE`是VSyscall虚拟地址对应的偏移值，`physaddr_vsyscall`是Vsyscall处理函数的物理地址，`PAGE_KERNEL_VVAR`是内存页的属性。

`PAGE_KERNEL_VVAR`对应的页属性在下方进行了展示，其中`__PP`代表当前内存页位于内存中，首个0代表内存页不可写不可读，`_USR`代表该内存页可以用户态程序访问，`___A`代表线性地址转换中该表项被使用，`__NX`代表内存页开启数据执行保护，第二个0代表该内存页未被写入数据，第三个0代表表项直接未被直接映射到内存页，`___G`代表该页的TLB是全局的。

```
#ifdef CONFIG_X86_VSYSCALL_EMULATION
	VSYSCALL_PAGE = (FIXADDR_TOP - VSYSCALL_ADDR) >> PAGE_SHIFT,
#endif

#define __PAGE_KERNEL_VVAR	 (__PP|   0|_USR|___A|__NX|   0|   0|___G)
#define PAGE_KERNEL_VVAR	__pgprot_mask(__PAGE_KERNEL_VVAR       | _ENC)

if (vsyscall_mode == EMULATE) {
		__set_fixmap(VSYSCALL_PAGE, physaddr_vsyscall,
			     PAGE_KERNEL_VVAR);
		set_vsyscall_pgtable_user_bits(swapper_pg_dir);
	}
```

`set_vsyscall_pgtable_user_bits`函数的作用是确保VSyscall所在内存页是设置了`_PAGE_USER`的。

当模式为`XONLY`时，内存页的设置方式会发生改变。

```
if (vsyscall_mode == XONLY)
	vm_flags_init(&gate_vma, VM_EXEC);
```

在这里VSyscall的内存信息会被标记在`gate_vma`当中，该结构体会在内核初始化时借助`__get_user_pages`和`in_gate_area`分配用户态可以使用的内存页。

```
static struct vm_area_struct gate_vma __ro_after_init = {
	.vm_start	= VSYSCALL_ADDR,
	.vm_end		= VSYSCALL_ADDR + PAGE_SIZE,
	.vm_page_prot	= PAGE_READONLY_EXEC,
	.vm_flags	= VM_READ | VM_EXEC,
	.vm_ops		= &gate_vma_ops,
};

struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
#ifdef CONFIG_COMPAT
	if (!mm || !test_bit(MM_CONTEXT_HAS_VSYSCALL, &mm->context.flags))
		return NULL;
#endif
	if (vsyscall_mode == NONE)
		return NULL;
	return &gate_vma;
}

int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma = get_gate_vma(mm);

	if (!vma)
		return 0;

	return (addr >= vma->vm_start) && (addr < vma->vm_end);
}

static long __get_user_pages(struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		int *locked)
{
	vma = gup_vma_lookup(mm, start);
	if (!vma && in_gate_area(mm, start)) {
		ret = get_gate_page(mm, start & PAGE_MASK,
				gup_flags, &vma,
				pages ? &page : NULL);
		if (ret)
			goto out;
		ctx.page_mask = 0;
		goto next_page;
	}
}
```

拿到`gate_vmd`的地址后就会通过`vm_flags_init`将内存页标记为可执行的状态。

通过下面的驱动代码，我们可以检验VSyscall的内存信息。

```
void vsyscall_info_show(void)
{
	struct vm_area_struct* vsyscall_info;
	int* vsyscall_mode;
	const char* vsc_mode_str[] = {
		"EMULATE",
		"XONLY",
		"NONE"
	};

	vsyscall_info = (struct vm_area_struct*)LDE_KLN_PTR("gate_vma");
	vsyscall_mode = (int*)LDE_KLN_PTR("vsyscall_mode");
	if (!vsyscall_info || !vsyscall_mode) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol, vma at 0x%px, mode: %s\n",
			vsyscall_info, vsc_mode_str[*vsyscall_mode]);
	}

	printk(KERN_INFO "VSYSCALL_ADDR: %lx, %s %lx - %lx\n", VSYSCALL_ADDR,
		vsyscall_info->vm_ops->name(NULL), vsyscall_info->vm_start, vsyscall_info->vm_end);
}
```

可以获取的内存信息还有很多，这里只打印了页名以及页范围，从下面可以看到VSyscall的内存信息的确是上面论证的结果。

```
驱动打印的消息：
[ 1804.290063] found symbols by [kprobe], kallsyms_lookup_name at 0xffffffffa3db7e14, ret: 0
[ 1811.881820] lde_proc_write called legnth 0x9, 0x000061bcc8981a60
[ 1811.882274] found symbol, vma at 0xffffffffa5531000, mode: XONLY
[ 1811.882278] VSYSCALL_ADDR: ffffffffff600000, [vsyscall] ffffffffff600000 - ffffffffff601000

应用程序的内存信息：
cat /proc/294/maps
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
cat /proc/1/maps
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

其中VSyscall的起始地址是`VSYSCALL_ADDR`宏规定的，所以VSyscall的地址永远都是固定的，不会产生变化。

### VSyscall的操作

下面展示VSyscall的处理代码，Linux在启动阶段根据处理器加载对应的VSyscall信息，比如下方展示的存放系统调用号的`rax`寄存器，以及触发系统调用的指令`syscall`都是根据x64架构的处理器特殊设置的。

```
__PAGE_ALIGNED_DATA
	.globl __vsyscall_page
	.balign PAGE_SIZE, 0xcc
	.type __vsyscall_page, @object
__vsyscall_page:

	mov $__NR_gettimeofday, %rax
	syscall
	ret
	int3

	.balign 1024, 0xcc
	mov $__NR_time, %rax
	syscall
	ret
	int3

	.balign 1024, 0xcc
	mov $__NR_getcpu, %rax
	syscall
	ret
	int3

	.balign 4096, 0xcc

	.size __vsyscall_page, 4096
```

## 内核支持 - VDSO

VDSO由`init_vdso_image_xx`进行初始化，该函数被注册到了驱动初始化列表内，内核启动时会遍历该列表，执行初始化动作，`init_vdso_image_xx`函数这里使用的`subsys_initcall`。

```
static __init int init_vdso_image_xx(void) {
	return init_vdso_image(&vdso_image_x);
};
subsys_initcall(init_vdso_image_xx);
```

### 驱动在内核启动过程中加载的方式

在Linux内核当中，经常可以看到某某驱动初始化函数由`xxx_initcall`进行注册，然后内核就会在启动阶段对它进行调用。

```
#define __initcall_section(__sec, __iid)			\
	#__sec ".init"

#define ____define_initcall(fn, __unused, __name, __sec)	\
	static initcall_t __name __used 			\
		__attribute__((__section__(__sec))) = fn;

#define ____define_initcall(fn, __stub, __name, __sec)		\
	__define_initcall_stub(__stub, fn)			\
	asm(".section	\"" __sec "\", \"a\"		\n"	\
	    __stringify(__name) ":			\n"	\
	    ".long	" __stringify(__stub) " - .	\n"	\
	    ".previous					\n");	\
	static_assert(__same_type(initcall_t, &fn));

#define __unique_initcall(fn, id, __sec, __iid)			\
	____define_initcall(fn,					\
		__initcall_stub(fn, __iid, id),			\
		__initcall_name(initcall, __iid, id),		\
		__initcall_section(__sec, __iid))

#define ___define_initcall(fn, id, __sec)			\
	__unique_initcall(fn, id, __sec, __initcall_id(fn))

#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)
#define core_initcall(fn)		__define_initcall(fn, 1)
#define subsys_initcall(fn)		__define_initcall(fn, 4)
```

根据指定的`xxx_initcall`不同，驱动初始化的级别也会不同，被注册的信息会被放入`.init.data`节内，并且针对不同级别进行区分，每个级别都有一段单独的空间。

```
生成的vmlinux.lds的内容：
.init.data : AT(ADDR(.init.data) - 0xffffffff80000000) {
	__initcall_start = .; KEEP(*(.initcallearly.init))
	__initcall0_start = .; KEEP(*(.initcall0.init)) KEEP(*(.initcall0s.init)) 
	__initcall1_start = .; KEEP(*(.initcall1.init)) KEEP(*(.initcall1s.init))
	__initcall2_start = .; KEEP(*(.initcall2.init)) KEEP(*(.initcall2s.init))
	__initcall3_start = .; KEEP(*(.initcall3.init)) KEEP(*(.initcall3s.init))
	__initcall4_start = .; KEEP(*(.initcall4.init)) KEEP(*(.initcall4s.init))
	__initcall5_start = .; KEEP(*(.initcall5.init)) KEEP(*(.initcall5s.init))
	__initcallrootfs_start = .; KEEP(*(.initcallrootfs.init)) KEEP(*(.initcallrootfss.init))
	__initcall6_start = .; KEEP(*(.initcall6.init)) KEEP(*(.initcall6s.init))
	__initcall7_start = .; KEEP(*(.initcall7.init)) KEEP(*(.initcall7s.init))
	__initcall_end = .;
}
```

内核启动时需要加载的驱动，都位于`.initcallxx`里面了。内核真正加载驱动时，首先会通过`do_initcalls`遍历所有的级别，每个级别内的驱动由`do_initcall_level`函数进行遍历并加载，遍历的依据就是vmlinux.lds文件内针对指定级别生成的地址，比如级别0对应着`__initcall0_start`。

```
static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

static void __init do_initcall_level(int level, char *command_line)
{
	initcall_entry_t *fn;

	parse_args(initcall_level_names[level],
		   command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, ignore_unknown_bootoption);

	trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
	int level;
	size_t len = saved_command_line_len + 1;
	char *command_line;

	command_line = kzalloc(len, GFP_KERNEL);
	if (!command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
		/* Parser modifies command_line, restore it each time */
		strcpy(command_line, saved_command_line);
		do_initcall_level(level, command_line);
	}

	kfree(command_line);
}
```

### VDSO的生成

VDSO的生成分成用户态和内核态两大部分，下面会对各部分分别进行解析。

#### vdso.so的生成

vdso.so是专门提供给用户态程序使用，它的生成分成32位和64位两个部分。

```
编译过程：
make arch/x86/entry/vdso/

64位开始生成：
LDS     arch/x86/entry/vdso/vdso.lds
AS      arch/x86/entry/vdso/vdso-note.o
CC      arch/x86/entry/vdso/vclock_gettime.o
CC      arch/x86/entry/vdso/vgetcpu.o
AS      arch/x86/entry/vdso/vsgx.o
VDSO    arch/x86/entry/vdso/vdso64.so.dbg
OBJCOPY arch/x86/entry/vdso/vdso64.so

32位开始生成（分成32和x32）：
LDS     arch/x86/entry/vdso/vdsox32.lds
X32     arch/x86/entry/vdso/vdso-note-x32.o
X32     arch/x86/entry/vdso/vclock_gettime-x32.o
X32     arch/x86/entry/vdso/vgetcpu-x32.o
X32     arch/x86/entry/vdso/vsgx-x32.o
VDSO    arch/x86/entry/vdso/vdsox32.so.dbg
OBJCOPY arch/x86/entry/vdso/vdsox32.so

LDS     arch/x86/entry/vdso/vdso32/vdso32.lds
AS      arch/x86/entry/vdso/vdso32/note.o
AS      arch/x86/entry/vdso/vdso32/system_call.o
AS      arch/x86/entry/vdso/vdso32/sigreturn.o
CC      arch/x86/entry/vdso/vdso32/vclock_gettime.o
CC      arch/x86/entry/vdso/vdso32/vgetcpu.o
VDSO    arch/x86/entry/vdso/vdso32.so.dbg
OBJCOPY arch/x86/entry/vdso/vdso32.so
```

不同位的so通过指定的文件编译产生，每个文件生成单独`.o`文件后，会先链接成`vdso32.so.dbg`文件，最后由`objcopy`生成最终的动态链接库。

```
vobjs-y := vdso-note.o vclock_gettime.o vgetcpu.o
vobjs32-y := vdso32/note.o vdso32/system_call.o vdso32/sigreturn.o
vobjs32-y += vdso32/vclock_gettime.o vdso32/vgetcpu.o
vobjs-$(CONFIG_X86_SGX)	+= vsgx.o
```

`linux-vdso.so.1`的名字也是Makefile内指定的。

```
VDSO_LDFLAGS_vdso.lds = -m elf_x86_64 -soname linux-vdso.so.1 --no-undefined \
							-z max-page-size=4096
```

#### 内核VDSO的产生

内核首先处理的文件是`vma.c`和`extable.c`，它们是内核操作VDSO的核心逻辑所在。

```
make arch/x86/entry/vdso/
CC      arch/x86/entry/vdso/vma.o
CC      arch/x86/entry/vdso/extable.o
```

在此之后，会有两个特别的文件，它们以`vdso-image-xx.c`为标志，这两个文件并不是默认就有的，而是在编译过程中产生的`.c`文件，然后再对它们进行编译。

```
vdso-image-64.c
vdso-image-32.c

HOSTCC  arch/x86/entry/vdso/vdso2c
VDSO2C  arch/x86/entry/vdso/vdso-image-64.c
CC      arch/x86/entry/vdso/vdso-image-64.o

VDSO2C  arch/x86/entry/vdso/vdso-image-x32.c
CC      arch/x86/entry/vdso/vdso-image-x32.o

VDSO2C  arch/x86/entry/vdso/vdso-image-32.c
CC      arch/x86/entry/vdso/vdso-image-32.o
CC      arch/x86/entry/vdso/vdso32-setup.o
```

它们通过`vdso2c`可执行文件进行产生，该可执行文件由`vdso2c.c`和`vdso2c.h`编译而成，程序内部通过`go`函数写入具体的内容，写入的内容是根据前面生成的vdso.so而产生的。

`vdso2c`程序接收3个参数，第一个参数是`vdsoxx.so.dbg`，第二个参数`vdso.so`，第三个参数是生成文件的名字，传入带有调试符号版本的`so`文件，主要目的是辅助展示`vdso_image`的信息。

```
vdso2c.h：
static void BITSFUNC(go)(void *raw_addr, size_t raw_len,
			 void *stripped_addr, size_t stripped_len,
			 FILE *outfile, const char *image_name)
{
	......
}
```

生成的文件由下面五大部分组成，其中`raw_data`是根据`vdso.so`生成的（包含动态链接库的原始数据），`extable`是根据`vdsoxx.so.dbg`生成的，结构体`struct vdso_image`用于描述VDSO的信息。

```
1. raw_data
2. extable
3. 
struct vdso_image vdso_image_xx {
	.data = raw_data,
	.size = 8192,
	.alt = 4033,
	.alt_len = 210,
	.extable_base = 4303,
	.extable_len = 8,
	.extable = extable,
	.sym_vvar_start = -16384,
	.sym_vvar_page = -16384,
	.sym_pvclock_page = -12288,
	.sym_hvclock_page = -8192,
	.sym_timens_page = -4096,
};
4.
static __init int init_vdso_image_xx(void) {
	return init_vdso_image(&vdso_image_xx);
};
5.
subsys_initcall(init_vdso_image_xx);
```

非调试版本的动态链接库只会负责原始二进制文件内信息的展示，至于`vdso_image`需要的其他信息，则要借助调试版本进行产生，调试版本展示的信息有两类，一是部分节的位置信息，二是被剥离出来的`__ex_table`节信息。

```
调试版本：
  Segment Sections...
   00     .hash .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_d .dynamic .note .eh_frame_hdr .eh_frame .text .altinstructions .altinstr_replacement __ex_table 
   01     .dynamic 
   02     .note 
   03     .eh_frame_hdr

非调试版本：
  Segment Sections...
   00     .hash .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_d .dynamic .note .eh_frame_hdr .eh_frame .text .altinstructions .altinstr_replacement 
   01     .dynamic 
   02     .note 
   03     .eh_frame_hdr
```

`vdso_image`中的`alt`对应着`.altinstructions`节，该节的全称是`Alternative Instructions`代替指令，是为指令集的扩展功能而准备的，`alternative`会将可以替换的指令放入`.altinstructions`节内，留给内核在运行时决定是否使用指令集的新指令。

```
#define alternative(oldinstr, newinstr, ft_flags)			\
	asm_inline volatile (ALTERNATIVE(oldinstr, newinstr, ft_flags) : : : "memory")
```

`__ex_table`节是调试版中被剥离出去的节，其中`ex`是异常的缩写，该节定义了异常的处理方式，`vdso_image`中特地将它添加了进来，用于处理VDSO的异常情况。

`vvar`对应着内核态与用户态共享数据的内存页，`pvclock`代表着管道监控数据进度的内存页，`hvclock`代表宿主机与虚拟机间通信的内存页，`timens`代表时钟命名空间的内存页。

### VDSO的初始化

在内核启动时，`subsys_initcall`会起到初始化的作用，并将VDSO的处理权限交给`init_vdso_image`函数，该函数内部实现比较简单，只是通过`apply_alternatives`函数对旧指令进行替换。

```
int __init init_vdso_image(const struct vdso_image *image)
{
	BUILD_BUG_ON(VDSO_CLOCKMODE_MAX >= 32);
	BUG_ON(image->size % PAGE_SIZE != 0);

	apply_alternatives((struct alt_instr *)(image->data + image->alt),
			   (struct alt_instr *)(image->data + image->alt +
						image->alt_len));

	return 0;
}
```

### 用户态程序获取VDSO

在Linux内核当中，处理程序运行的是著名的`load_elf_binary`函数。该函数会在读取ELF文件段信息之后，设置内存信息之间对VDSO进行加载。

```
#if defined(ARCH_HAS_SETUP_ADDITIONAL_PAGES) && !defined(ARCH_SETUP_ADDITIONAL_PAGES)
#define ARCH_SETUP_ADDITIONAL_PAGES(bprm, ex, interpreter) \
	arch_setup_additional_pages(bprm, interpreter)
#endif

static int load_elf_binary(struct linux_binprm *bprm)
{
	......
#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = ARCH_SETUP_ADDITIONAL_PAGES(bprm, elf_ex, !!interpreter);
	if (retval < 0)
		goto out;
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */
	......
}
```

`load_elf_binary`函数会让`arch_setup_additional_pages`函数通过`map_vdso`去映射VDSO给当前进程。

`map_vdso`函数第一步做的是通过`get_unmapped_area`接口申请一段未使用的内存。`get_unmapped_area`函数的第二个参数是待分配的内存地址，地址为零就代表申请未使用的内存，否则则按指定的地址进行查找，三号参数指定了申请的内存空间大小。

```
static int map_vdso(const struct vdso_image *image, unsigned long addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long text_start;
	int ret = 0;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	addr = get_unmapped_area(NULL, addr,
				 image->size - image->sym_vvar_start, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	text_start = addr - image->sym_vvar_start;

	/*
	 * MAYWRITE to allow gdb to COW and set breakpoints
	 */
	vma = _install_special_mapping(mm,
				       text_start,
				       image->size,
				       VM_READ|VM_EXEC|
				       VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				       &vdso_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	vma = _install_special_mapping(mm,
				       addr,
				       -image->sym_vvar_start,
				       VM_READ|VM_MAYREAD|VM_IO|VM_DONTDUMP|
				       VM_PFNMAP,
				       &vvar_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		do_munmap(mm, text_start, image->size, NULL);
	} else {
		current->mm->context.vdso = (void __user *)text_start;
		current->mm->context.vdso_image = image;
	}

up_fail:
	mmap_write_unlock(mm);
	return ret;
}

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	if (!vdso64_enabled)
		return 0;

	return map_vdso(&vdso_image_64, 0);
}
```

值得注意的是，这里符号地址使用的均是负数，当`get_unmapped_area`分配出`image`和`vvar`的空间后，会使用`text_start`作为分割，`addr`到`text_start`是vvar的范围，`text_start`往上才是vdso的范围。

```
static const struct vm_special_mapping vdso_mapping = {
	.name = "[vdso]",
	.fault = vdso_fault,
	.mremap = vdso_mremap,
};
static const struct vm_special_mapping vvar_mapping = {
	.name = "[vvar]",
	.fault = vvar_fault,
};
```

这一点也可以在`_install_special_mapping`中获得验证，其中`text_start`对应着`vdso_mapping`，`addr`对应着`vvar_mapping`，`_install_special_mapping`函数会将分配好的内存空间信息`vma`填入内存管理结构体`mm`中，如果`_install_special_mapping`函数没有出错，那么就会继续往内存管理结构体`mm`填写vdso的信息。

此时内核就完成了加载程序的vdso和vvar的任务。

## 用户态程序的使用

VDSO和Vsyscall实现的系统调用并不多，目前支持的系统调用均列在了下方，它们是需要经常使用的系统调用。

```
vdso：
0x00007ffff7fc57b0  __vdso_gettimeofday
0x00007ffff7fc5aa0  __vdso_time
0x00007ffff7fc5ad0  __vdso_clock_gettime
0x00007ffff7fc5e80  __vdso_clock_getres
0x00007ffff7fc5ef0  __vdso_getcpu
0x00007ffff7fc5f20  __vdso_sgx_enter_enclave

vsysall：
$__NR_gettimeofday
$__NR_time
$__NR_getcpu
```

用户态程序对VDSO及VSyscall的使用，是在LD与GLibC的帮助下运行的，程序使用GlibC封装的函数时，LD会将它们解析到VDSO或VSyscall内。

## 补充 - 栈上的VDSO地址

LD程序的`_start`函数缸开始运行时，可以发现栈空间内已经有一部分空间被赋值了，其中最具有标志性的信息就是环境变量字符串了。显然这些信息是内核进行赋值的。

```
x /gx 0x7fffffffe0f0
0x7fffffffe0f0: 0x00007ffff7fc5000

7ffff7fc5000-7ffff7fc7000 r-xp 00000000 00:00 0                          [vdso]
```

考虑到程序所需的信息是内核进行操作的，程序有使用它们的必要性，所以内核会将这些信息放入程序可以使用的栈空间内。内核压入栈空间内的数据通过`create_elf_tables`函数进行操作，数据分成下面的四种，第一种是程序的命令行参数数量，第二种是命令行参数，第三种是环境变量参数，第四种是辅助向量（包含程序需要的辅助信息）。

```
argc：
if (put_user(argc, sp++))
	return -EFAULT;

argv：
p = mm->arg_end = mm->arg_start;
if (put_user((elf_addr_t)p, sp++))
		return -EFAULT;

env：
mm->env_end = mm->env_start = p;
if (put_user((elf_addr_t)p, sp++))
	return -EFAULT;

auxv：
if (copy_to_user(sp, mm->saved_auxv, ei_index * sizeof(elf_addr_t)))
		return -EFAULT;
```

辅助向量有非常多的种类，从`AT_BASE`一直到`AT_UID`，具体的向量及其含义可以通过`man`手册进行查看，Linux内核当中，向量数据通过`NEW_AUX_ENT`接口进行放置（首个参数为向量，第二个参数为数值）。在`create_elf_tables`函数中VDSO的起始地址是第一个压入的向量，在`create_elf_tables`函数的内部，它通过`saved_auxv`保存向量信息，向量id占据前八个字节，数值占据后八个字节，索引`saved_auxv`时，通过压入的顺序进行索引，比如VDSO的起始地址就对应着`saved_auxv[1]`。

```
create_elf_tables：
	......
	elf_info = (elf_addr_t *)mm->saved_auxv;
#define NEW_AUX_ENT(id, val) \
	do { \
		*elf_info++ = id; \
		*elf_info++ = val; \
	} while (0)
	......
#ifdef ARCH_DLINFO
	ARCH_DLINFO;
#endif
	......

#define ARCH_DLINFO							\
do {									\
	if (vdso64_enabled)						\
		NEW_AUX_ENT(AT_SYSINFO_EHDR,				\
			    (unsigned long __force)current->mm->context.vdso); \
	NEW_AUX_ENT(AT_MINSIGSTKSZ, get_sigframe_size());		\
} while (0)
```

Linux下可以通过设置`LD_SHOW_AUXV=1`查看辅助向量的内容，这里借用的是LD的参数。

```
LD_SHOW_AUXV=1 id
AT_SYSINFO_EHDR:      0x773d60ebb000
AT_MINSIGSTKSZ:       1440
AT_HWCAP:             178bfbff
AT_PAGESZ:            4096
AT_CLKTCK:            100
AT_PHDR:              0x5f3d8b4ad040
AT_PHENT:             56
AT_PHNUM:             13
AT_BASE:              0x773d60ebd000
AT_FLAGS:             0x0
AT_ENTRY:             0x5f3d8b4afa30
AT_UID:               1000
AT_EUID:              1000
AT_GID:               1000
AT_EGID:              1000
AT_SECURE:            0
AT_RANDOM:            0x7ffd13bb3289
AT_HWCAP2:            0x2
AT_EXECFN:            /usr/bin/id
AT_PLATFORM:          x86_64
AT_??? (0x1b): 0x1c
AT_??? (0x1c): 0x20
uid=1000(nora) gid=1000(nora) groups=1000(nora),3(sys),90(network),98(power),991(lp),998(wheel)
```

# 利用思路

VSyscall和VDSO都是内核映射到用户空间的，其中VSyscall使用的是固定地址，在任何情况下都是一样的，而VDSO则是程序每次运行时新分配地址，所以地址是会动态变化的。

VSyscall映射中虽然没有什么可以利用的空间，但是如果由于它固定的地址，以及含有`ret`指令的特性，我们可以不断利用它滑动到我们期望的位置，再进行利用。

## 废物 - VDSO

在这里我大胆下一个判断VDSO就是一个废物。

首先不管64位还是32位的VDSO，它们对于用户态程序都是不可感知的，想要了解动态链接库中的内容就只有两个选择，一是将内存转储出来，二是找到内核编译出来的动态链接库。

其次目前的VDSO内支持的功能少之又少，对于64位而言，想要构造ROP是相当困难的，相当于在沙漠里找水喝，并且VDSO与其他动态链接库相比，并没有很明显的优势，而且内核向栈上提交的信息也不止VDSO一个，为什么不利用其他的信息呢？

当然32位的VDSO中存在的函数会更多一些，利用的机会也会更大，但应该将它作为第一选择吗。

```
objdump -d ./vdso32.so | grep ">:"
00000570 <__kernel_vsyscall@@LINUX_2.5>:
00000590 <__kernel_sigreturn@@LINUX_2.5>:
000005a0 <__kernel_rt_sigreturn@@LINUX_2.5>:
00000790 <__vdso_gettimeofday@@LINUX_2.6>:
00000d00 <__vdso_time@@LINUX_2.6>:
00000d50 <__vdso_clock_gettime@@LINUX_2.6>:
00001390 <__vdso_clock_gettime64@@LINUX_2.6>:
00001a30 <__vdso_clock_getres@@LINUX_2.6>:
00001ac0 <__vdso_getcpu@@LINUX_2.6>:
00001c1c <.altinstr_replacement>:
```

# 示例讲解

下面给出了示例代码的反汇编结果，程序会接收两次输入，然后通过`user_check`函数检查输入的信息，如果正确就会调用Shell，反之则不会。

```
0000000000001179 <user_check>:
    1179:       55                      push   %rbp
    117a:       48 89 e5                mov    %rsp,%rbp
    117d:       48 83 ec 20             sub    $0x20,%rsp
    1181:       48 89 7d e8             mov    %rdi,-0x18(%rbp)
    1185:       48 89 75 e0             mov    %rsi,-0x20(%rbp)
    1189:       48 8b 45 e8             mov    -0x18(%rbp),%rax
    118d:       be 00 10 00 00          mov    $0x1000,%esi
    1192:       48 89 c7                mov    %rax,%rdi
    1195:       e8 c6 fe ff ff          call   1060 <strnlen@plt>
    119a:       48 89 c2                mov    %rax,%rdx
    119d:       48 8b 45 e8             mov    -0x18(%rbp),%rax
    11a1:       48 89 c6                mov    %rax,%rsi
    11a4:       48 8d 05 5d 0e 00 00    lea    0xe5d(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    11ab:       48 89 c7                mov    %rax,%rdi
    11ae:       e8 7d fe ff ff          call   1030 <strncmp@plt>
    11b3:       89 45 fc                mov    %eax,-0x4(%rbp)
    11b6:       48 8b 45 e0             mov    -0x20(%rbp),%rax
    11ba:       be 00 10 00 00          mov    $0x1000,%esi
    11bf:       48 89 c7                mov    %rax,%rdi
    11c2:       e8 99 fe ff ff          call   1060 <strnlen@plt>
    11c7:       48 89 c2                mov    %rax,%rdx
    11ca:       48 8b 45 e0             mov    -0x20(%rbp),%rax
    11ce:       48 89 c6                mov    %rax,%rsi
    11d1:       48 8d 05 35 0e 00 00    lea    0xe35(%rip),%rax        # 200d <_IO_stdin_used+0xd>
    11d8:       48 89 c7                mov    %rax,%rdi
    11db:       e8 50 fe ff ff          call   1030 <strncmp@plt>
    11e0:       01 45 fc                add    %eax,-0x4(%rbp)
    11e3:       8b 45 fc                mov    -0x4(%rbp),%eax
    11e6:       c9                      leave
    11e7:       c3                      ret

00000000000011e8 <main>:
    11e8:       55                      push   %rbp
    11e9:       48 89 e5                mov    %rsp,%rbp
    11ec:       48 83 ec 50             sub    $0x50,%rsp
    11f0:       48 8d 05 1e 0e 00 00    lea    0xe1e(%rip),%rax        # 2015 <_IO_stdin_used+0x15>
    11f7:       48 89 c7                mov    %rax,%rdi
    11fa:       e8 41 fe ff ff          call   1040 <puts@plt>
    11ff:       48 8d 45 d0             lea    -0x30(%rbp),%rax
    1203:       ba 00 10 00 00          mov    $0x1000,%edx
    1208:       48 89 c6                mov    %rax,%rsi
    120b:       bf 00 00 00 00          mov    $0x0,%edi
    1210:       e8 5b fe ff ff          call   1070 <read@plt>
    1215:       48 8d 05 04 0e 00 00    lea    0xe04(%rip),%rax        # 2020 <_IO_stdin_used+0x20>
    121c:       48 89 c7                mov    %rax,%rdi
    121f:       e8 1c fe ff ff          call   1040 <puts@plt>
    1224:       48 8d 45 b0             lea    -0x50(%rbp),%rax
    1228:       ba 00 10 00 00          mov    $0x1000,%edx
    122d:       48 89 c6                mov    %rax,%rsi
    1230:       bf 00 00 00 00          mov    $0x0,%edi
    1235:       e8 36 fe ff ff          call   1070 <read@plt>
    123a:       48 8d 55 b0             lea    -0x50(%rbp),%rdx
    123e:       48 8d 45 d0             lea    -0x30(%rbp),%rax
    1242:       48 89 d6                mov    %rdx,%rsi
    1245:       48 89 c7                mov    %rax,%rdi
    1248:       e8 2c ff ff ff          call   1179 <user_check>
    124d:       85 c0                   test   %eax,%eax
    124f:       75 11                   jne    1262 <main+0x7a>
    1251:       48 8d 05 d2 0d 00 00    lea    0xdd2(%rip),%rax        # 202a <_IO_stdin_used+0x2a>
    1258:       48 89 c7                mov    %rax,%rdi
    125b:       e8 f0 fd ff ff          call   1050 <system@plt>
    1260:       eb 0f                   jmp    1271 <main+0x89>
    1262:       48 8d 05 cf 0d 00 00    lea    0xdcf(%rip),%rax        # 2038 <_IO_stdin_used+0x38>
    1269:       48 89 c7                mov    %rax,%rdi
    126c:       e8 cf fd ff ff          call   1040 <puts@plt>
    1271:       b8 00 00 00 00          mov    $0x0,%eax
    1276:       c9                      leave
    1277:       c3                      ret
```

下面展示了程序及系统目前的保护措施，出来金丝雀之外的其他保护已经全部开启了，并且程序具有明显的栈溢出漏洞，固定地址的VSyscall刚好可以辅助我们完成栈溢出的利用。

```
ALSR：开启

Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enable
```

## VSyscall滑动

在`main`函数之前LD和LibC做了大量的工作，其中与`main`函数最为贴近的就是`__libc_init_first`函数，这个函数是`__libc_start_main`进行调用的。

```
   25ebd:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
   25ec1:	48 89 da             	mov    %rbx,%rdx
   25ec4:	44 89 e6             	mov    %r12d,%esi
   25ec7:	e8 c4 fe ff ff       	call   25d90 <__libc_init_first@@GLIBC_2.2.5+0x10>
```

`__libc_init_first`函数会对主程序的`main`函数进行调用，下面对其汇编代码进行了分析。

```
0000000000025d80 <__libc_init_first@@GLIBC_2.2.5>:
   25d80:	f3 0f 1e fa          	endbr64
   25d84:	c3                   	ret
   25d85:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
   25d8c:	00 00 00 
   25d8f:	90                   	nop
   25d90:	55                   	push   %rbp
   25d91:	48 89 e5             	mov    %rsp,%rbp
   25d94:	48 81 ec 90 00 00 00 	sub    $0x90,%rsp
   设置栈空间，分配大小0x90
   25d9b:	48 89 7d 88          	mov    %rdi,-0x78(%rbp)
   25d9f:	89 75 84             	mov    %esi,-0x7c(%rbp)
   25da2:	48 89 95 78 ff ff ff 	mov    %rdx,-0x88(%rbp)
   保存接收的三个参数到栈上
   25da9:	64 48 8b 3c 25 28 00 	mov    %fs:0x28,%rdi
   25db0:	00 00 
   25db2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
   保存金丝雀到rbp-0x8的位置，对栈空间进行保护
   25db6:	48 8d 7d 90          	lea    -0x70(%rbp),%rdi
   此时rbp-0x70中的地址保存的是程序段的入口地址
   25dba:	e8 91 70 01 00       	call   3ce50 <_setjmp@@GLIBC_2.2.5>
   25dbf:	f3 0f 1e fa          	endbr64
   25dc3:	85 c0                	test   %eax,%eax
   25dc5:	75 48                	jne    25e0f <__libc_init_first@@GLIBC_2.2.5+0x8f>
   判断setjmp的返回值，如果是0就不跳转，反之则跳转
   此时rbp-0x70中的地址保存的是命令行参数和环境变量信息，rbp-0x78中的地址保存的是main函数的起始地址
   25dc7:	64 48 8b 04 25 00 03 	mov    %fs:0x300,%rax
   25dce:	00 00 
   25dd0:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
   保存%fs:0x300到rbp-0x28的位置
   25dd4:	64 48 8b 04 25 f8 02 	mov    %fs:0x2f8,%rax
   25ddb:	00 00 
   25ddd:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
   保存%fs:0x2f8到rbp-0x28的位置
   25de1:	48 8d 45 90          	lea    -0x70(%rbp),%rax
   将保存命令行参数和环境变量的地址交给rax
   25de5:	64 48 89 04 25 00 03 	mov    %rax,%fs:0x300
   将保存命令行参数和环境变量的地址交给%fs:0x300
   25dec:	00 00 
   25dee:	48 8b 05 9b 11 1c 00 	mov    0x1c119b(%rip),%rax        # 1e6f90 <__environ@@GLIBC_2.2.5-0x7de8>
   将保存环境变量的地址交给rax
   25df5:	48 8b b5 78 ff ff ff 	mov    -0x88(%rbp),%rsi
   25dfc:	8b 7d 84             	mov    -0x7c(%rbp),%edi
   设置待传递的参数（argc，argv）
   25dff:	48 8b 10             	mov    (%rax),%rdx
   设置待传递的参数（envp）
   25e02:	48 8b 45 88          	mov    -0x78(%rbp),%rax
   将main函数的起始地址交给rax
   25e06:	ff d0                	call   *%rax
   调用main函数
   25e08:	89 c7                	mov    %eax,%edi
   将返回值作为exit的函数的第一个参数
   25e0a:	e8 31 9b 01 00       	call   3f940 <exit@@GLIBC_2.2.5>
   退出
   ......
```

显然`rbp-0x78`的位置保存着`main`函数的起始地址，它与`main`函数的`rbp`间隔了0x32的空间。如果我们利用VSyscall对这片区域进行填充，然后借助`rbp-0x78`中的高位地址，仅对第2个字节进行覆盖，就可以使得程序的控制流返回到`system("/bin/sh")`的位置。

`system`函数在程序中被调用的偏移值是0x1258，程序的基地址一定是按照页大小（0x1000）进行偏移的，所以高4个比特位不能确定，需要通过爆破的方式进行猜测，不过4个比特位对应着`1/16`的概率，已经相当高了。

```
main：
(gdb) x /6gx $rbp
0x7fffffffde40: 0x00007fffffffdee0      0x00007ffff7dd0e08
0x7fffffffde50: 0x00007fffffffde90      0x00007fffffffdf68
0x7fffffffde60: 0x0000000155554040      0x00005555555551ea
```

程序访问错误的地址会收到段错误信号`SIGSEGV`，因此这里可以通过`recv`进行接收，并通过`except`对收到的错误进行处理，方便程序在失败后继续运行。

### 补充 - 利用Vsyscall的局限性

值得注意的是，VSyscall的固定地址并不是一直可用的，比如下方展示了一段出现在内核消息`dmesg`中的内容，它显示程序访问地址`ffffffffff600000`时出现错误。

```
[ 9153.062234] ret2vdso_example[14713] vsyscall fault (exploit attempt?) ip:ffffffffff600000 cs:33 sp:7fffffffdea0 ax:ffffffffffffffda si:7fffffffde40 di:555555556009
```

VSyscall已经渐渐退出Linux舞台，甚至在有些发行版本中直接将它去除掉了，即使没有去除，保留下来的VSyscall也只剩下零星几个的系统调用可以利用的空间实在是少的可怜（现在可能一共就9条汇编指令）。所谓麻绳专挑细处断，Linux内核在本就孱弱的可利用空间上由砍了一刀，做出了下方的`check_fault`检查。

```
bool emulate_vsyscall(unsigned long error_code,
		      struct pt_regs *regs, unsigned long address)
{
	......
	switch (vsyscall_nr) {
	case 0:
		if (!write_ok_or_segv(regs->di, sizeof(struct __kernel_old_timeval)) ||
		    !write_ok_or_segv(regs->si, sizeof(struct timezone))) {
			ret = -EFAULT;
			goto check_fault;
		}
	}
	......
	ret = -EFAULT;
	switch (vsyscall_nr) {
		......
	}
check_fault:
	if (ret == -EFAULT) {
		/* Bad news -- userspace fed a bad pointer to a vsyscall. */
		warn_bad_vsyscall(KERN_INFO, regs,
				  "vsyscall fault (exploit attempt?)");
		goto sigsegv;
	}
	......
}

static inline
void do_user_addr_fault(struct pt_regs *regs,
			unsigned long error_code,
			unsigned long address)
{
	......
	if (is_vsyscall_vaddr(address)) {
		if (emulate_vsyscall(error_code, regs, address))
			return;
	}
	......
}
```

这个安全检查做的事情并不复杂，可以分成两个部分，首先检查的内容是系统调用的所需参数（根据调用协议的寄存器获取数据），检查的依据是用户态程序的最大地址`0x7ffffffff000`，检测到地址不是用户态的地址就会报错。

```
static __always_inline unsigned long task_size_max(void)
{
	unsigned long ret;

	alternative_io("movq %[small],%0","movq %[large],%0",
			X86_FEATURE_LA57,
			"=r" (ret),
			[small] "i" ((1ul << 47)-PAGE_SIZE),
			[large] "i" ((1ul << 56)-PAGE_SIZE));

	return ret;
}
#define TASK_SIZE_MAX		task_size_max()

static inline int __access_ok(const void __user *ptr, unsigned long size)
{
	unsigned long limit = TASK_SIZE_MAX;
	unsigned long addr = (unsigned long)ptr;

	if (IS_ENABLED(CONFIG_ALTERNATE_USER_ADDRESS_SPACE) ||
	    !IS_ENABLED(CONFIG_MMU))
		return true;

	return (size <= limit) && (addr <= (limit - size));
}
#define __access_ok __access_ok

static bool write_ok_or_segv(unsigned long ptr, size_t size)
{
	if (!access_ok((void __user *)ptr, size)) {
		struct thread_struct *thread = &current->thread;

		thread->error_code	= X86_PF_USER | X86_PF_WRITE;
		thread->cr2		= ptr;
		thread->trap_nr		= X86_TRAP_PF;

		force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)ptr);
		return false;
	} else {
		return true;
	}
}
```

第二部是系统调用执行是的`put_user`，该函数会讲输入放入指定的地址内，如果地址是不可写的就会出错。

```
SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
		struct getcpu_cache __user *, unused)
{
	int err = 0;
	int cpu = raw_smp_processor_id();

	if (cpup)
		err |= put_user(cpu, cpup);
	if (nodep)
		err |= put_user(cpu_to_node(cpu), nodep);
	return err ? -EFAULT : 0;
}
```

由于`si`的地址是`0x555555556009`，由于该地址所在内存页是不可写的，内核判断它可能会是恶意的利用，所以这里就直接设置段错误了，不让你继续往下运行。

在使用VSyscall进行滑动时，需要注意`rdi`、`rsi`的数值，避免内核检查时出错，如果确定`rdi`、`rsi`中数值有误，那么就无法使用VSyscall进行滑动。最好是通过VSyscall中的`__NR_time`进行滑动（偏移0x400），因为它只接收一个参数，所以只会对`rdi`进行检查，因此对`__NR_time`进行利用会更加轻松一些。
