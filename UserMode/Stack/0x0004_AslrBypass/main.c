#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define MAX_READ_LEN 4096

static void leak_func(void)
{
	char buf[48];

	puts(">>>>");
	scanf("%s", buf);
	printf(buf);
}

static void read_func(void)
{
    char buf[256];

	puts("<<<<");
    read(STDIN_FILENO, buf, MAX_READ_LEN);
}

int main(void)
{
    leak_func();
    read_func();

    printf("has return\n");

    return 0;
}
