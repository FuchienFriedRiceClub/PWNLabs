#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_LEN	0x100

static void vuln(void)
{
	char buf[100];

	setbuf(stdin, buf);
	read(STDIN_FILENO, buf, MAX_LEN);
}

int main(void)
{
	char msg[] = "hello world\n";

    write(STDOUT_FILENO, msg, strnlen(msg, MAX_LEN));
	vuln();

	return 0;
}
