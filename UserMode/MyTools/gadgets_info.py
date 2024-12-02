glibc_ver236_info = {
	'pop_rax_ret_offset': 0x3f197,
	'pop_rdi_ret_offset': 0x277e5,
	'pop_rsi_ret_offset': 0x28f99,
	'xor_edx_syscall_offset': 0x8cff8,

	'libc_call_main_offset': 0x2724a,	# __libc_init_first -> call *%rax
}

binary_lists = {
	'glibc_ver236': glibc_ver236_info
}

cur_ver = 'glibc_ver236'

linux_adm64_gadgets = {
	'pop_rax_ret_offset': binary_lists[cur_ver]['pop_rax_ret_offset'],
	'pop_rdi_ret_offset': binary_lists[cur_ver]['pop_rdi_ret_offset'],
	'pop_rsi_ret_offset': binary_lists[cur_ver]['pop_rsi_ret_offset'],
	'xor_edx_syscall_offset': binary_lists[cur_ver]['xor_edx_syscall_offset'],

	'libc_call_main_offset': binary_lists[cur_ver]['libc_call_main_offset'],
}
