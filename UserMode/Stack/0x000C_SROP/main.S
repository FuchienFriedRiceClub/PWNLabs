.text
.global _start

_start:
	xor %rax,%rax
	mov $0x400,%edx
	mov %rsp,%rsi
	mov %rax,%rdi
	syscall
	ret
