#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_READ_LEN 	4096

static void vuln() {
	FILE* fp;
	char buf[0x100];

	fp = fopen("/dev/stdin", "r");
	if (!fp) {
		printf("open stdin failed\n");
	}
	puts(">>>>");
	fgets(buf, MAX_READ_LEN, fp);
}

int main(void) {
    vuln();

	printf("has return\n");

    return 0;
}
