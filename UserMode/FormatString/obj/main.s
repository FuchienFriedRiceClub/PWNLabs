	.file	"main.c"
	.text
.Ltext0:
	.file 0 "/home/astaroth/Labs/PWN/UserMode/FormatString" "main.c"
	.section	.rodata
.LC0:
	.string	""
	.section	.data.rel.local,"aw"
	.align 8
	.type	fmt_str, @object
	.size	fmt_str, 8
fmt_str:
	.quad	.LC0
	.section	.rodata
.LC1:
	.string	"get %d - %llx\n"
	.text
	.type	va_args4int, @function
va_args4int:
.LFB6:
	.file 1 "main.c"
	.loc 1 21 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$224, %rsp
	movl	%edi, -212(%rbp)
	movq	%rsi, -168(%rbp)
	movq	%rdx, -160(%rbp)
	movq	%rcx, -152(%rbp)
	movq	%r8, -144(%rbp)
	movq	%r9, -136(%rbp)
	testb	%al, %al
	je	.L7
	movaps	%xmm0, -128(%rbp)
	movaps	%xmm1, -112(%rbp)
	movaps	%xmm2, -96(%rbp)
	movaps	%xmm3, -80(%rbp)
	movaps	%xmm4, -64(%rbp)
	movaps	%xmm5, -48(%rbp)
	movaps	%xmm6, -32(%rbp)
	movaps	%xmm7, -16(%rbp)
.L7:
	.loc 1 25 1
	movl	$8, -200(%rbp)
	movl	$48, -196(%rbp)
	leaq	16(%rbp), %rax
	movq	%rax, -192(%rbp)
	leaq	-176(%rbp), %rax
	movq	%rax, -184(%rbp)
	.loc 1 27 8
	jmp	.L3
.L6:
	.loc 1 28 7
	movl	-200(%rbp), %eax
	cmpl	$47, %eax
	ja	.L4
	movq	-184(%rbp), %rax
	movl	-200(%rbp), %edx
	movl	%edx, %edx
	addq	%rdx, %rax
	movl	-200(%rbp), %edx
	addl	$8, %edx
	movl	%edx, -200(%rbp)
	jmp	.L5
.L4:
	movq	-192(%rbp), %rax
	leaq	8(%rax), %rdx
	movq	%rdx, -192(%rbp)
.L5:
	movq	(%rax), %rax
	movq	%rax, -208(%rbp)
	.loc 1 29 3
	movq	-208(%rbp), %rdx
	movl	-212(%rbp), %eax
	movl	%eax, %esi
	leaq	.LC1(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 31 6
	subl	$1, -212(%rbp)
.L3:
	.loc 1 27 13
	cmpl	$0, -212(%rbp)
	jg	.L6
	.loc 1 35 1
	nop
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	va_args4int, .-va_args4int
	.section	.rodata
	.align 8
.LC2:
	.string	"0x00 before the effective address"
	.string	""
.LC3:
	.string	"0x0000444444404545"
	.string	""
.LC4:
	.string	"EE@DDD"
	.string	""
	.string	""
	.string	""
	.align 8
.LC5:
	.string	"0x00 at the end of effective address"
	.string	""
.LC6:
	.string	"0x4444444444404500"
	.string	""
.LC7:
	.string	""
	.string	"E@DDDDD"
	.string	""
	.align 8
.LC8:
	.string	"0x00 in the effective address"
	.string	""
.LC9:
	.string	"0x4444444444400045"
	.string	""
.LC10:
	.string	"E"
	.string	"@DDDDD"
	.string	""
	.align 8
.LC11:
	.string	"desc: %s\n\torig: %s\n\tbytes: start-%s-end\n"
	.text
	.type	addr_with_null_analyze, @function
addr_with_null_analyze:
.LFB7:
	.loc 1 38 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$96, %rsp
	.loc 1 40 12
	leaq	.LC2(%rip), %rax
	movq	%rax, -80(%rbp)
	leaq	.LC3(%rip), %rax
	movq	%rax, -72(%rbp)
	leaq	.LC4(%rip), %rax
	movq	%rax, -64(%rbp)
	leaq	.LC5(%rip), %rax
	movq	%rax, -56(%rbp)
	leaq	.LC6(%rip), %rax
	movq	%rax, -48(%rbp)
	leaq	.LC7(%rip), %rax
	movq	%rax, -40(%rbp)
	leaq	.LC8(%rip), %rax
	movq	%rax, -32(%rbp)
	leaq	.LC9(%rip), %rax
	movq	%rax, -24(%rbp)
	leaq	.LC10(%rip), %rax
	movq	%rax, -16(%rbp)
	.loc 1 58 6
	movl	$3, -84(%rbp)
	.loc 1 59 8
	jmp	.L9
.L10:
	.loc 1 66 22
	movl	-84(%rbp), %eax
	subl	$1, %eax
	.loc 1 60 3
	movslq	%eax, %rdx
	movq	%rdx, %rax
	addq	%rax, %rax
	addq	%rdx, %rax
	salq	$3, %rax
	addq	%rbp, %rax
	subq	$64, %rax
	movq	(%rax), %rcx
	.loc 1 65 22
	movl	-84(%rbp), %eax
	subl	$1, %eax
	.loc 1 60 3
	movslq	%eax, %rdx
	movq	%rdx, %rax
	addq	%rax, %rax
	addq	%rdx, %rax
	salq	$3, %rax
	addq	%rbp, %rax
	subq	$72, %rax
	movq	(%rax), %rsi
	.loc 1 64 22
	movl	-84(%rbp), %eax
	subl	$1, %eax
	.loc 1 60 3
	movslq	%eax, %rdx
	movq	%rdx, %rax
	addq	%rax, %rax
	addq	%rdx, %rax
	salq	$3, %rax
	addq	%rbp, %rax
	subq	$80, %rax
	movq	(%rax), %rax
	movq	%rsi, %rdx
	movq	%rax, %rsi
	leaq	.LC11(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 69 6
	subl	$1, -84(%rbp)
.L9:
	.loc 1 59 13
	cmpl	$0, -84(%rbp)
	jg	.L10
	.loc 1 71 1
	nop
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	addr_with_null_analyze, .-addr_with_null_analyze
	.section	.rodata
.LC12:
	.string	"%s %s"
.LC13:
	.string	"0x"
.LC14:
	.string	"%hhx"
	.text
	.type	bytes_print, @function
bytes_print:
.LFB8:
	.loc 1 74 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$112, %rsp
	movq	%rdi, -104(%rbp)
	.loc 1 74 1
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	.loc 1 75 6
	movl	$0, -84(%rbp)
	.loc 1 78 2
	movq	-104(%rbp), %rdx
	leaq	-80(%rbp), %rax
	movq	%rdx, %r8
	leaq	__func__.1(%rip), %rdx
	movq	%rdx, %rcx
	leaq	.LC12(%rip), %rdx
	movl	$64, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	snprintf@PLT
	.loc 1 80 2
	leaq	.LC13(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 81 8
	jmp	.L12
.L13:
	.loc 1 82 21
	movl	-84(%rbp), %eax
	cltq
	movzbl	-80(%rbp,%rax), %eax
	.loc 1 82 3
	movsbl	%al, %eax
	movl	%eax, %esi
	leaq	.LC14(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 84 4
	addl	$1, -84(%rbp)
.L12:
	.loc 1 81 11
	cmpl	$63, -84(%rbp)
	jle	.L13
	.loc 1 86 2
	movl	$10, %edi
	call	putchar@PLT
	.loc 1 87 1
	nop
	movq	-8(%rbp), %rax
	subq	%fs:40, %rax
	je	.L14
	call	__stack_chk_fail@PLT
.L14:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE8:
	.size	bytes_print, .-bytes_print
	.section	.rodata
	.align 8
.LC15:
	.string	"|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|\n"
	.text
	.type	stack_mem_read, @function
stack_mem_read:
.LFB9:
	.loc 1 90 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 91 2
	leaq	.LC15(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 95 1
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE9:
	.size	stack_mem_read, .-stack_mem_read
	.section	.rodata
.LC16:
	.string	"welcome, %s!\n"
	.text
	.type	arbitrary_mem_read_wrtie, @function
arbitrary_mem_read_wrtie:
.LFB10:
	.loc 1 98 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$96, %rsp
	movq	%rdi, -88(%rbp)
	.loc 1 98 1
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	.loc 1 101 2
	movq	-88(%rbp), %rdx
	leaq	-80(%rbp), %rax
	movq	%rdx, %rcx
	leaq	.LC16(%rip), %rdx
	movl	$64, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	snprintf@PLT
	.loc 1 103 2
	leaq	-80(%rbp), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 104 1
	nop
	movq	-8(%rbp), %rax
	subq	%fs:40, %rax
	je	.L17
	call	__stack_chk_fail@PLT
.L17:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE10:
	.size	arbitrary_mem_read_wrtie, .-arbitrary_mem_read_wrtie
	.type	fmt_str_vuln_test, @function
fmt_str_vuln_test:
.LFB11:
	.loc 1 107 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$96, %rsp
	movq	%rdi, -88(%rbp)
	.loc 1 107 1
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	.loc 1 110 2
	movq	-88(%rbp), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 112 2
	leaq	-80(%rbp), %rax
	movl	$64, %edx
	movq	%rax, %rsi
	movl	$0, %edi
	call	read@PLT
	.loc 1 113 2
	leaq	-80(%rbp), %rax
	movq	%rax, %rdi
	call	arbitrary_mem_read_wrtie
	.loc 1 114 1
	nop
	movq	-8(%rbp), %rax
	subq	%fs:40, %rax
	je	.L19
	call	__stack_chk_fail@PLT
.L19:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE11:
	.size	fmt_str_vuln_test, .-fmt_str_vuln_test
	.section	.rodata
.LC17:
	.string	"malloc failed"
	.text
	.type	fmt_str_in_heap_test, @function
fmt_str_in_heap_test:
.LFB12:
	.loc 1 117 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	.loc 1 120 8
	movl	$64, %edi
	call	malloc@PLT
	movq	%rax, -8(%rbp)
	.loc 1 121 5
	cmpq	$0, -8(%rbp)
	jne	.L21
	.loc 1 122 3
	leaq	.LC17(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
.L21:
	.loc 1 125 2
	movq	-8(%rbp), %rax
	movl	$64, %edx
	movq	%rax, %rsi
	movl	$0, %edi
	call	read@PLT
	.loc 1 126 2
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 127 1
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE12:
	.size	fmt_str_in_heap_test, .-fmt_str_in_heap_test
	.section	.rodata
.LC18:
	.string	"/bin/sh"
	.text
	.type	gift_get, @function
gift_get:
.LFB13:
	.loc 1 130 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 131 2
	leaq	.LC18(%rip), %rax
	movq	%rax, %rdi
	call	system@PLT
	.loc 1 132 1
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE13:
	.size	gift_get, .-gift_get
	.section	.rodata
	.align 8
.LC19:
	.string	"format string vuln test for read"
	.align 8
.LC20:
	.string	"&argv 0x%llx\nargv 0x%llx\nargv0 0x%llx\n"
	.align 8
.LC21:
	.string	"format string vuln test for write"
.LC22:
	.string	"leave %s\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB14:
	.loc 1 135 1
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movq	%rsi, -16(%rbp)
	.loc 1 136 2
	movl	$57, %r8d
	movl	$99, %ecx
	movl	$10, %edx
	movl	$3, %esi
	movl	$4, %edi
	movl	$0, %eax
	call	va_args4int
	.loc 1 138 5
	cmpl	$2, -4(%rbp)
	jne	.L24
	.loc 1 139 19
	movq	-16(%rbp), %rax
	addq	$8, %rax
	.loc 1 139 3
	movq	(%rax), %rax
	movq	%rax, %rdi
	call	bytes_print
.L24:
	.loc 1 141 2
	call	addr_with_null_analyze
	.loc 1 142 2
	call	stack_mem_read
	.loc 1 144 2
	leaq	.LC19(%rip), %rax
	movq	%rax, %rdi
	call	fmt_str_vuln_test
	.loc 1 150 4
	movq	-16(%rbp), %rax
	.loc 1 145 2
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movq	%rax, %rsi
	leaq	-16(%rbp), %rax
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movq	%rax, %rsi
	leaq	.LC20(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	.loc 1 151 2
	call	fmt_str_in_heap_test
	.loc 1 152 2
	call	fmt_str_in_heap_test
	.loc 1 153 2
	call	fmt_str_in_heap_test
	.loc 1 154 2
	call	fmt_str_in_heap_test
	.loc 1 155 2
	call	fmt_str_in_heap_test
	.loc 1 156 2
	call	fmt_str_in_heap_test
	.loc 1 157 2
	leaq	.LC21(%rip), %rax
	movq	%rax, %rdi
	call	fmt_str_vuln_test
	.loc 1 159 2
	leaq	__func__.0(%rip), %rax
	movq	%rax, %rsi
	leaq	.LC22(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
	movl	$0, %eax
	.loc 1 160 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE14:
	.size	main, .-main
	.section	.rodata
	.align 8
	.type	__func__.1, @object
	.size	__func__.1, 12
__func__.1:
	.string	"bytes_print"
	.type	__func__.0, @object
	.size	__func__.0, 5
__func__.0:
	.string	"main"
	.text
.Letext0:
	.file 2 "/usr/lib/gcc/x86_64-linux-gnu/12/include/stddef.h"
	.file 3 "/usr/lib/gcc/x86_64-linux-gnu/12/include/stdarg.h"
	.file 4 "<built-in>"
	.file 5 "/usr/include/x86_64-linux-gnu/bits/types.h"
	.file 6 "/usr/include/stdio.h"
	.file 7 "/usr/include/stdlib.h"
	.file 8 "/usr/include/unistd.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x440
	.value	0x5
	.byte	0x1
	.byte	0x8
	.long	.Ldebug_abbrev0
	.uleb128 0x12
	.long	.LASF43
	.byte	0x1d
	.long	.LASF0
	.long	.LASF1
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x4
	.long	.LASF2
	.byte	0x2
	.byte	0xd6
	.byte	0x1b
	.long	0x3a
	.uleb128 0x1
	.byte	0x8
	.byte	0x7
	.long	.LASF8
	.uleb128 0x4
	.long	.LASF3
	.byte	0x3
	.byte	0x28
	.byte	0x1b
	.long	0x4d
	.uleb128 0x13
	.long	.LASF44
	.long	0x56
	.uleb128 0x5
	.long	0x66
	.long	0x66
	.uleb128 0x6
	.long	0x3a
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	.LASF45
	.byte	0x18
	.byte	0x4
	.byte	0
	.long	0x9b
	.uleb128 0xa
	.long	.LASF4
	.long	0x9b
	.byte	0
	.uleb128 0xa
	.long	.LASF5
	.long	0x9b
	.byte	0x4
	.uleb128 0xa
	.long	.LASF6
	.long	0xa2
	.byte	0x8
	.uleb128 0xa
	.long	.LASF7
	.long	0xa2
	.byte	0x10
	.byte	0
	.uleb128 0x1
	.byte	0x4
	.byte	0x7
	.long	.LASF9
	.uleb128 0x15
	.byte	0x8
	.uleb128 0x1
	.byte	0x1
	.byte	0x8
	.long	.LASF10
	.uleb128 0x1
	.byte	0x2
	.byte	0x7
	.long	.LASF11
	.uleb128 0x1
	.byte	0x1
	.byte	0x6
	.long	.LASF12
	.uleb128 0x1
	.byte	0x2
	.byte	0x5
	.long	.LASF13
	.uleb128 0x16
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x1
	.byte	0x8
	.byte	0x5
	.long	.LASF14
	.uleb128 0x4
	.long	.LASF15
	.byte	0x5
	.byte	0xc2
	.byte	0x12
	.long	0xc7
	.uleb128 0xb
	.long	0xdf
	.uleb128 0x1
	.byte	0x1
	.byte	0x6
	.long	.LASF16
	.uleb128 0xc
	.long	0xdf
	.uleb128 0x4
	.long	.LASF17
	.byte	0x6
	.byte	0x34
	.byte	0x18
	.long	0x41
	.uleb128 0x4
	.long	.LASF18
	.byte	0x6
	.byte	0x4d
	.byte	0x13
	.long	0xce
	.uleb128 0xb
	.long	0xe6
	.uleb128 0x1
	.byte	0x8
	.byte	0x5
	.long	.LASF19
	.uleb128 0x1
	.byte	0x8
	.byte	0x7
	.long	.LASF20
	.uleb128 0xb
	.long	0xda
	.uleb128 0x17
	.long	.LASF46
	.byte	0x18
	.byte	0x1
	.byte	0xc
	.byte	0x10
	.long	0x14c
	.uleb128 0xf
	.long	.LASF21
	.byte	0xd
	.long	0xda
	.byte	0
	.uleb128 0x18
	.string	"str"
	.byte	0x1
	.byte	0xe
	.byte	0x8
	.long	0xda
	.byte	0x8
	.uleb128 0xf
	.long	.LASF22
	.byte	0xf
	.long	0xda
	.byte	0x10
	.byte	0
	.uleb128 0x4
	.long	.LASF23
	.byte	0x1
	.byte	0x10
	.byte	0x3
	.long	0x11b
	.uleb128 0xd
	.long	.LASF31
	.byte	0x12
	.byte	0xe
	.long	0xda
	.uleb128 0x9
	.byte	0x3
	.quad	fmt_str
	.uleb128 0x7
	.long	.LASF24
	.byte	0x7
	.value	0x324
	.byte	0xc
	.long	0xc0
	.long	0x184
	.uleb128 0x2
	.long	0x103
	.byte	0
	.uleb128 0x7
	.long	.LASF25
	.byte	0x7
	.value	0x229
	.byte	0xe
	.long	0xa2
	.long	0x19b
	.uleb128 0x2
	.long	0x2e
	.byte	0
	.uleb128 0x7
	.long	.LASF26
	.byte	0x8
	.value	0x173
	.byte	0x10
	.long	0xf7
	.long	0x1bc
	.uleb128 0x2
	.long	0xc0
	.uleb128 0x2
	.long	0xa2
	.uleb128 0x2
	.long	0x2e
	.byte	0
	.uleb128 0x7
	.long	.LASF27
	.byte	0x6
	.value	0x17a
	.byte	0xc
	.long	0xc0
	.long	0x1de
	.uleb128 0x2
	.long	0xda
	.uleb128 0x2
	.long	0x2e
	.uleb128 0x2
	.long	0x103
	.uleb128 0xe
	.byte	0
	.uleb128 0x7
	.long	.LASF28
	.byte	0x6
	.value	0x164
	.byte	0xc
	.long	0xc0
	.long	0x1f6
	.uleb128 0x2
	.long	0x103
	.uleb128 0xe
	.byte	0
	.uleb128 0x19
	.long	.LASF47
	.byte	0x1
	.byte	0x86
	.byte	0x5
	.long	0xc0
	.quad	.LFB14
	.quad	.LFE14-.LFB14
	.uleb128 0x1
	.byte	0x9c
	.long	0x248
	.uleb128 0x8
	.long	.LASF29
	.byte	0x86
	.byte	0xe
	.long	0xc0
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x8
	.long	.LASF30
	.byte	0x86
	.byte	0x1a
	.long	0x116
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0x10
	.long	.LASF39
	.long	0x258
	.uleb128 0x9
	.byte	0x3
	.quad	__func__.0
	.byte	0
	.uleb128 0x5
	.long	0xe6
	.long	0x258
	.uleb128 0x6
	.long	0x3a
	.byte	0x4
	.byte	0
	.uleb128 0xc
	.long	0x248
	.uleb128 0x11
	.long	.LASF35
	.byte	0x81
	.quad	.LFB13
	.quad	.LFE13-.LFB13
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x9
	.long	.LASF32
	.byte	0x74
	.quad	.LFB12
	.quad	.LFE12-.LFB12
	.uleb128 0x1
	.byte	0x9c
	.long	0x2a0
	.uleb128 0x3
	.string	"buf"
	.byte	0x76
	.byte	0x8
	.long	0xda
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x9
	.long	.LASF33
	.byte	0x6a
	.quad	.LFB11
	.quad	.LFE11-.LFB11
	.uleb128 0x1
	.byte	0x9c
	.long	0x2db
	.uleb128 0x8
	.long	.LASF21
	.byte	0x6a
	.byte	0x2b
	.long	0x103
	.uleb128 0x3
	.byte	0x91
	.sleb128 -104
	.uleb128 0x3
	.string	"buf"
	.byte	0x6c
	.byte	0x7
	.long	0x2db
	.uleb128 0x3
	.byte	0x91
	.sleb128 -96
	.byte	0
	.uleb128 0x5
	.long	0xdf
	.long	0x2eb
	.uleb128 0x6
	.long	0x3a
	.byte	0x3f
	.byte	0
	.uleb128 0x9
	.long	.LASF34
	.byte	0x61
	.quad	.LFB10
	.quad	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x326
	.uleb128 0x8
	.long	.LASF31
	.byte	0x61
	.byte	0x32
	.long	0x103
	.uleb128 0x3
	.byte	0x91
	.sleb128 -104
	.uleb128 0x3
	.string	"buf"
	.byte	0x63
	.byte	0x7
	.long	0x2db
	.uleb128 0x3
	.byte	0x91
	.sleb128 -96
	.byte	0
	.uleb128 0x11
	.long	.LASF36
	.byte	0x59
	.quad	.LFB9
	.quad	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x9
	.long	.LASF37
	.byte	0x49
	.quad	.LFB8
	.quad	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x399
	.uleb128 0x8
	.long	.LASF38
	.byte	0x49
	.byte	0x25
	.long	0x103
	.uleb128 0x3
	.byte	0x91
	.sleb128 -120
	.uleb128 0x3
	.string	"i"
	.byte	0x4b
	.byte	0x6
	.long	0xc0
	.uleb128 0x3
	.byte	0x91
	.sleb128 -100
	.uleb128 0x3
	.string	"buf"
	.byte	0x4c
	.byte	0x7
	.long	0x2db
	.uleb128 0x3
	.byte	0x91
	.sleb128 -96
	.uleb128 0x10
	.long	.LASF39
	.long	0x3a9
	.uleb128 0x9
	.byte	0x3
	.quad	__func__.1
	.byte	0
	.uleb128 0x5
	.long	0xe6
	.long	0x3a9
	.uleb128 0x6
	.long	0x3a
	.byte	0xb
	.byte	0
	.uleb128 0xc
	.long	0x399
	.uleb128 0x9
	.long	.LASF40
	.byte	0x25
	.quad	.LFB7
	.quad	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x3e9
	.uleb128 0x3
	.string	"cnt"
	.byte	0x27
	.byte	0x6
	.long	0xc0
	.uleb128 0x3
	.byte	0x91
	.sleb128 -100
	.uleb128 0xd
	.long	.LASF41
	.byte	0x28
	.byte	0xc
	.long	0x3e9
	.uleb128 0x3
	.byte	0x91
	.sleb128 -96
	.byte	0
	.uleb128 0x5
	.long	0x14c
	.long	0x3f9
	.uleb128 0x6
	.long	0x3a
	.byte	0x2
	.byte	0
	.uleb128 0x1a
	.long	.LASF48
	.byte	0x1
	.byte	0x14
	.byte	0xd
	.quad	.LFB6
	.quad	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x1b
	.string	"num"
	.byte	0x1
	.byte	0x14
	.byte	0x1d
	.long	0xc0
	.uleb128 0x3
	.byte	0x91
	.sleb128 -228
	.uleb128 0xe
	.uleb128 0xd
	.long	.LASF42
	.byte	0x16
	.byte	0xa
	.long	0xeb
	.uleb128 0x3
	.byte	0x91
	.sleb128 -216
	.uleb128 0x3
	.string	"tmp"
	.byte	0x17
	.byte	0x15
	.long	0x10f
	.uleb128 0x3
	.byte	0x91
	.sleb128 -224
	.byte	0
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 13
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 4
	.uleb128 0x3b
	.uleb128 0x21
	.sleb128 0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0x21
	.sleb128 8
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x18
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 8
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x34
	.uleb128 0x19
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0x21
	.sleb128 1
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0x21
	.sleb128 13
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x1f
	.uleb128 0x1b
	.uleb128 0x1f
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x13
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x7c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x1b
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x2c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF19:
	.string	"long long int"
.LASF33:
	.string	"fmt_str_vuln_test"
.LASF34:
	.string	"arbitrary_mem_read_wrtie"
.LASF2:
	.string	"size_t"
.LASF30:
	.string	"argv"
.LASF27:
	.string	"snprintf"
.LASF21:
	.string	"desc"
.LASF48:
	.string	"va_args4int"
.LASF18:
	.string	"ssize_t"
.LASF39:
	.string	"__func__"
.LASF38:
	.string	"data"
.LASF3:
	.string	"__gnuc_va_list"
.LASF10:
	.string	"unsigned char"
.LASF37:
	.string	"bytes_print"
.LASF8:
	.string	"long unsigned int"
.LASF11:
	.string	"short unsigned int"
.LASF17:
	.string	"va_list"
.LASF23:
	.string	"print_str"
.LASF22:
	.string	"str_bytes"
.LASF46:
	.string	"_print_str"
.LASF26:
	.string	"read"
.LASF4:
	.string	"gp_offset"
.LASF25:
	.string	"malloc"
.LASF47:
	.string	"main"
.LASF9:
	.string	"unsigned int"
.LASF7:
	.string	"reg_save_area"
.LASF20:
	.string	"long long unsigned int"
.LASF44:
	.string	"__builtin_va_list"
.LASF6:
	.string	"overflow_arg_area"
.LASF15:
	.string	"__ssize_t"
.LASF42:
	.string	"valist"
.LASF16:
	.string	"char"
.LASF24:
	.string	"system"
.LASF28:
	.string	"printf"
.LASF41:
	.string	"addr_null_prt"
.LASF43:
	.string	"GNU C17 12.2.0 -mtune=generic -march=x86-64 -g -fstack-protector -fasynchronous-unwind-tables"
.LASF13:
	.string	"short int"
.LASF29:
	.string	"argc"
.LASF32:
	.string	"fmt_str_in_heap_test"
.LASF36:
	.string	"stack_mem_read"
.LASF14:
	.string	"long int"
.LASF12:
	.string	"signed char"
.LASF40:
	.string	"addr_with_null_analyze"
.LASF45:
	.string	"__va_list_tag"
.LASF5:
	.string	"fp_offset"
.LASF35:
	.string	"gift_get"
.LASF31:
	.string	"fmt_str"
	.section	.debug_line_str,"MS",@progbits,1
.LASF0:
	.string	"main.c"
.LASF1:
	.string	"/home/astaroth/Labs/PWN/UserMode/FormatString"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
