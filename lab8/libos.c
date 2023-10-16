#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void nextCC(pid_t child) {
    int wait_status;
    if (ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptraceCONT");
    if (waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
}
void nextStep(pid_t child) {
    int wait_status;
    if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("PTRACE_SINGLESTEP");
    if (waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
	pid_t child;
	if (argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	if ((child = fork()) < 0) errquit("fork");
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
        char magiclocal[16] = {0};
        long *magiclocal_longptr = (long *) magiclocal;
        int n = 10;
        memset(magiclocal, '0', 10);
		int wait_status;
        unsigned long long magicremote_ptr, startPoint;
        long ret;
        struct user_regs_struct regs;

		if (waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        nextCC(child);
        nextCC(child);

        if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
        magicremote_ptr = regs.rax;
        printf("magicremote_ptr: %llx\n", magicremote_ptr);

        nextCC(child);

        if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
        startPoint = regs.rip;
        printf("startPoint: %llx\n", startPoint);


        for (int state=0; state<(1<<n); state++) {
            nextCC(child);
            for (int i=0; i<n; i++) {
                magiclocal[n-i-1] = '0' + ((state>>i)&1);
            }
            if (ptrace(PTRACE_POKETEXT, child, magicremote_ptr, *magiclocal_longptr) < 0) errquit("PTRACE_PEEKTEXT");

            ret = ptrace(PTRACE_PEEKTEXT, child, magicremote_ptr+8, 0);
            ret &= ~0xFFFFFF;
            ret |= *(magiclocal_longptr+1);
            if (ptrace(PTRACE_POKETEXT, child, magicremote_ptr+8, ret) < 0) errquit("PTRACE_PEEKTEXT");
            nextCC(child);
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
            if (regs.rax == 0) {
                // nextCC(child);
                // nextCC(child);
                break;
            }
            regs.rip = startPoint;
            if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("PTRACE_SETREGS");
            nextStep(child);
        }
	}
	return 0;
}
