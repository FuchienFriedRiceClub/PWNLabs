#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_READ_LEN 	4096
#define USER			"test"
#define PASSWD			"1234567"

static int user_check(const char* user, const char* passwd) {
	int error;

	error = strncmp(USER, user, strnlen(user, MAX_READ_LEN));
	error += strncmp(PASSWD, passwd, strnlen(passwd, MAX_READ_LEN));

	return error;
}

int main(void) {
    char user[48];
	char passwd[20];

	puts("user name:");
    read(STDIN_FILENO, user, MAX_READ_LEN);
	puts("password:");
	read(STDIN_FILENO, passwd, MAX_READ_LEN);
	if (!user_check(user, passwd)) {
		system("/bin/sh");
	}
	else {
		puts("input error username && passwd");
	}

    return 0;
}
