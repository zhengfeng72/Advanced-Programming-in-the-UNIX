#include "apue.h"

#define	BUFFSIZE	1048576

int
main(int argc, char *argv[])
{
	int		n;
	char	buf[BUFFSIZE];

	int bsize = atoi(argv[1]);
	printf("bufsize = %d\n", bsize);
	fflush(stdout);

	while ((n = read(STDIN_FILENO, buf, bsize)) > 0)
		if (write(STDOUT_FILENO, buf, n) != n)
			err_sys("write error");

	if (n < 0)
		err_sys("read error");

	exit(0);
}
