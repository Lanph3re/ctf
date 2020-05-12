#include <stdlib.h>
#include <locale.h>
#include <stdio.h>

int main() {
	char *src[0x100];
	wchar_t *dst[0x100];
	setlocale(0, "en_US.UTF-8");

	read(0, src, 0x100);
	mbstowcs(dst, src, 0x100);
	write(1, dst, 0x100);

	return 0;
}
