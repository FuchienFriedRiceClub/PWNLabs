#include <stdio.h>
#include <unistd.h>
#include <string.h>

static void vuln(void)
{
	char buf[0x100];

	read(STDIN_FILENO, buf, 0x1000);
}

int main(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	puts("hello brop!");
	vuln();
	puts("bye, brop");
}
