#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define MY_FILE_NAME	"/tmp/AbCd"

int main(void)
{
	char buf[0x100];
	FILE* my_fp;

	if (!access(MY_FILE_NAME, F_OK | R_OK | W_OK)) {
		fgets(buf, 0x100, stdin);
		
		my_fp = fopen(MY_FILE_NAME, "r+");

		fwrite(buf, sizeof(char), strnlen(buf, 0x100), my_fp);
		fclose(my_fp);
	}
	else {
		printf("cannot access %s, errno %d\n", MY_FILE_NAME, errno);
	}
}
