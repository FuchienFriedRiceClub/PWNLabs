#include <stdio.h>

static void vuln(void)
{
	char buf[48] = { "......" };

	printf("hello, I want to bypass full-relro %s\n", buf);
}

int main(void)
{
	vuln();

	return 0;
}
