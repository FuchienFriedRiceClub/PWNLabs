#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#define MAX_ADDR_LEN					16
#define MAX_BUF_LEN						64
#define macro_va_args4int(int, ...)		va_args4int(int, __VA_ARGS__)

typedef struct _print_str {
	char* desc;
	char* str;
	char* str_bytes;
} print_str;

static char* fmt_str = "";

static void va_args4int(int num, ...)
{
	va_list valist;
	unsigned long long tmp;

	va_start(valist, num);

	while (num > 0) {
		tmp = va_arg(valist, unsigned long long);
		printf("get %d - %llx\n", num, tmp);

		num--;
	}

	va_end(valist);
}

static void addr_with_null_analyze(void)
{
	int cnt;
	print_str addr_null_prt[] = {
		{
			.desc = "0x00 before the effective address\0",
			.str = "0x0000444444404545\0",
			.str_bytes = "\x45\x45\x40\x44\x44\x44\x00\x00\0",
		},
		{
			.desc = "0x00 at the end of effective address\0",
			.str = "0x4444444444404500\0",
			.str_bytes = "\x00\x45\x40\x44\x44\x44\x44\x44\0",
		},
		{
			.desc = "0x00 in the effective address\0",
			.str = "0x4444444444400045\0",
			.str_bytes = "\x45\x00\x40\x44\x44\x44\x44\x44\0",
		},
	};

	cnt = sizeof(addr_null_prt) / sizeof(print_str);
	while (cnt > 0) {
		printf(
			"desc: %s\n"
			"\torig: %s\n"
			"\tbytes: start-%s-end\n",
			addr_null_prt[cnt - 1].desc,
			addr_null_prt[cnt - 1].str,
			addr_null_prt[cnt - 1].str_bytes
		);

		cnt--;
	}
}

static void bytes_print(const char* data)
{
	int i = 0;
	char buf[MAX_BUF_LEN];

	snprintf(buf, MAX_BUF_LEN, "%s %s", __func__, data);

	printf("0x");
	while (i < MAX_BUF_LEN) {
		printf("%hhx", buf[i]);

		i++;
	}
	printf("\n");
}

static void stack_mem_read(void)
{
	printf(
		"|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx"
		"|0x%llx|0x%llx|0x%llx|0x%llx|0x%llx|\n"
	);
}

static void arbitrary_mem_read_wrtie(const char* fmt_str)
{
	char buf[MAX_BUF_LEN];

	snprintf(buf, MAX_BUF_LEN, "welcome, %s!\n", fmt_str);

	printf(buf);
}

static void fmt_str_vuln_test(const char* desc)
{
	char buf[MAX_BUF_LEN];

	printf("%s\n", desc);

	read(STDIN_FILENO, buf, MAX_BUF_LEN);
	arbitrary_mem_read_wrtie(buf);
}

static void fmt_str_in_heap_test(void)
{
	char* buf;

	buf = malloc(sizeof(char) * MAX_BUF_LEN);
	if (!buf) {
		printf("malloc failed\n");
	}

	read(STDIN_FILENO, buf, MAX_BUF_LEN);
	printf(buf);
}

static void gift_get(void)
{
	system("/bin/sh");
}

int main(int argc, char* argv[])
{
	macro_va_args4int(4, 3, 10, 99, 57);

	if (argc == 2) {
		bytes_print(argv[1]);
	}
	addr_with_null_analyze();
	stack_mem_read();

	fmt_str_vuln_test("format string vuln test for read");
	printf("&argv 0x%llx\n"
		"argv 0x%llx\n"
		"argv0 0x%llx\n",
		(unsigned long long)(&argv),
		(unsigned long long)(argv),
		*(unsigned long long*)(argv));
	fmt_str_in_heap_test();
	fmt_str_in_heap_test();
	fmt_str_in_heap_test();
	fmt_str_in_heap_test();
	fmt_str_in_heap_test();
	fmt_str_in_heap_test();
	fmt_str_vuln_test("format string vuln test for write");

	printf("leave %s\n", __func__);
}
