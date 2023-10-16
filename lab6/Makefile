CC	= gcc
CFLAGS	= -g -masm=intel

sort.s: sort.c
	$(CC) $(CFLAGS) -m32 -S $<

sort:
	gcc -S -o sort.s -masm=intel sort.c

clean:
	rm sort.s