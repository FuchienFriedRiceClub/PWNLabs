#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define MAX_READ_LEN 4096

static void canary_leak(void) {
	char user_name[48];
    char password[12];

	puts("please enter user name: ");
	read(STDIN_FILENO, user_name, MAX_READ_LEN);
	printf("current user name: %s\n", user_name);

	puts("please enter password: ");
    read(STDIN_FILENO, password, MAX_READ_LEN);
}

static void stack_check_func_hijack(void)
{
	char buf[12];
	void* pointer;

	puts("please enter message: ");
	read(STDIN_FILENO, buf, MAX_READ_LEN);

	puts("please enter address: ");
	read(STDIN_FILENO, &pointer, MAX_READ_LEN);
	puts("please enter value: ");
	read(STDIN_FILENO, pointer, MAX_READ_LEN);
}

int main(int argc, char** argv)
{
	if (!argv[1]) {
		printf("need args..., will exit\n");
		return 0;
	}

	printf("printf address: 0x%lx\n", &printf);

	switch (argv[1][0]) {
	case 'c':
		goto TAG_CANARY_LEAK;
		break;
	case 'h':
		stack_check_func_hijack();
		break;
	default:
TAG_CANARY_LEAK:
		canary_leak();
		break;
	}

	printf("has return\n");

    return 0;
}
