#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void simple_overflow(char* in_val)
{
	char buf[100];

	printf("buf addr: 0x%lx\n", &buf);
	strcpy(buf, in_val);
	printf("buffer content: %s\n", buf);
}

int main(int argc, char* argv[])
{
	if (!argv[1]) {
		printf("need argv[1], will exit...\n");
		return 0;
	}

	simple_overflow(argv[1]);

	printf("has return\n");

	return 0;
}
