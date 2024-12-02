#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_DATA_LEN		0x100

static void msg_print(const char* msg);

typedef struct _your_msg {
	char msg_info[MAX_DATA_LEN];
	void (*msg_info_print)(const char*);
}  your_msg;

typedef struct _my_msg {
	void (*msg_info_print)(const char*);
	char msg_info[MAX_DATA_LEN];
} my_msg;

your_msg um = {
	.msg_info = "is your\n\0",
	.msg_info_print = msg_print,
};

static void shell_get(const char* msg)
{
	system(msg);
}

static void msg_print(const char* msg)
{
	printf("%s", msg);
}

static void vuln(void* ptr)
{
	my_msg *mm = (my_msg*)ptr;

	mm->msg_info_print(mm->msg_info);
}

int main(void)
{
	void *tmp;

	tmp = &um;
	um.msg_info_print = msg_print;
	um.msg_info_print(um.msg_info);

	printf("please input something\n");
	read(STDIN_FILENO, um.msg_info, MAX_DATA_LEN);
	vuln(tmp);
}
