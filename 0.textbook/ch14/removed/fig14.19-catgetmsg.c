#include "apue.h"
#ifndef __FreeBSD__
#include <stropts.h>
#endif

#define	BUFFSIZE	4096

int
main(void)
{
#ifdef __FreeBSD__
	err_quit("this platform is not supported");
	return -1;
#else
	int		n, flag;
	char		ctlbuf[BUFFSIZE], datbuf[BUFFSIZE];
	struct strbuf	ctl, dat;

	ctl.buf = ctlbuf;
	ctl.maxlen = BUFFSIZE;
	dat.buf = datbuf;
	dat.maxlen = BUFFSIZE;
	for ( ; ; ) {
		flag = 0;		/* return any message */
		if ((n = getmsg(STDIN_FILENO, &ctl, &dat, &flag)) < 0)
			err_sys("getmsg error");
		fprintf(stderr, "flag = %d, ctl.len = %d, dat.len = %d\n",
				flag, ctl.len, dat.len);
		if (dat.len == 0)
			exit(0);
		else if (dat.len > 0)
			if (write(STDOUT_FILENO, dat.buf, dat.len) != dat.len)
				err_sys("write error");
	}
#endif
}
