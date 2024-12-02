#include <stdio.h>

__attribute__ ((constructor))
static void befor_main_run (void)
{
	printf("[--] befor function main run\n");
}

__attribute__ ((destructor))
static void after_main_run (void)
{
	printf("[--] after function main run\n");
}

int main(void)
{
	printf("[--] function main run\n"
		"befor_main_run pointer = %p\n"
		"after_main_run pointer = %p\n",
		&befor_main_run, &after_main_run
	);

	return 0;
}
