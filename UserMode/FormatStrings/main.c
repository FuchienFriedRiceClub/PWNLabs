#include <stdio.h>

int main(void)
{
	int i;
	const char* buf = "0x%1$llx-0x%2$llx-0x%3$llx-0x%4$llx-0x%5$llx-"
		"0x%6$llx-0x%7$llx-0x%8$llx-0x%9$llx-0x%10$llx\n";

	printf(buf);

	printf("%.10u%n\n", 1, &i);
	printf("i = 0x%x\n", i);
}
