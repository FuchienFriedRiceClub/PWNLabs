#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USER_CORRECT_PASSWD		"oPhTUsrFjh1iKE"

int vuln(const char* buf, char len)
{
	printf("buf size %d\n", len);
	if (strncmp(USER_CORRECT_PASSWD, buf, len) == 0) {
		system("/bin/sh");
	}
}

int main(int argc, char** argv)
{
	printf("hello int abnormal\n");

	if (argc == 2) {
		vuln(argv[1], strnlen(argv[1], 0x1000));
	}
	else {
		printf("need input\n");
	}

	return 0;
}
