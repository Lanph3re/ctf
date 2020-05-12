#include <stdlib.h>
#include <locale.h>
#include <stdio.h>

int main() {
	wchar_t *src[0x100] = {0,};
	char *dst[0x100] = {0,};
	setlocale(0, "en_US.UTF-8");

	read(0, src, 0x100);
	wcstombs(dst, src, 0x100);
	write(1, dst, 0x100);

	return 0;
}
