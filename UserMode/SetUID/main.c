#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/*
 * chown root:root ./private_data.bin
 * chmod 600 ./private_data.bin
 *
 * chown root:root ./set_uid_example
 * chmod 4755 ./set_uid_example
 */

void vuln_by_user_input(const char* input)
{
	char cmd[0x100];

	snprintf(cmd, 0x100, "echo %s", input);
	system(cmd);
}

void vuln_by_permission_leak(void)
{
	int my_fd;

	printf("will get password\n");

	my_fd = open("./private_data.bin", O_RDWR | O_APPEND);
	if (my_fd > 0) {
		printf("get fd num %d\n", my_fd);
	}
	else {
		printf("open file failed [errno %d], will exit.\n", errno);

		return;
	}

	setuid(getuid());
	system("/bin/sh");
}

int main(int argc, char** argv)
{
	switch (argc) {
	case 1:
		vuln_by_permission_leak();
		break;
	case 2:
		vuln_by_user_input(argv[1]);
		break;
	default:
		break;
	}

	return 0;
}
