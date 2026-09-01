#include <stddef.h>

int main(void)
{
	volatile unsigned char *invalid = (volatile unsigned char *)0;

	*invalid = 1;
	return 70;
}
