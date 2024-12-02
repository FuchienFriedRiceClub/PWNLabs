#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define MAX_READ_LEN 4096

static void simple_overflow(void) {
    char buf[12];

    read(STDIN_FILENO, buf, MAX_READ_LEN);
}

int main(void)
{
	printf("printf address: 0x%lx\n", &printf);
    simple_overflow();

	printf("has return\n");

    return 0;
}
