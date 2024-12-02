#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#define MAX_READ_LEN	0x40

static void vuln(void)
{
	char buf[0x20];
	char* msg = "input somthing";

	puts(msg);
	read(STDIN_FILENO, buf, MAX_READ_LEN);
}

int main(void)
{
	vuln();

	printf("has return\n");

	return 0;
}
