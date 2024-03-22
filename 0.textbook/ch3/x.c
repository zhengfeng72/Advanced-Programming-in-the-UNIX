#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
	int fd;
	off_t o = 0L;
	pid_t pid;

	if(argc < 2) {
		fprintf(stderr, "usage: %s filename\n", argv[0]);
		return(1);
	}
	if((fd = open(argv[1], O_RDONLY, 0644)) < 0) {
		fprintf(stderr, "cannot open file %s\n", argv[1]);
		return(1);
	}

	if((pid = fork()) == 0) {	// child
		while(1) {
			printf("child: seek from %ld to %ld\n", o, o+1);
			o = lseek(fd, o+1, SEEK_SET);
			sleep(1);
		}
	} else {			// parent
		while(1) {
			o = lseek(fd, 0, SEEK_CUR);
			printf("parent: curr is %ld\n", o);
			sleep(1);
		}
	}
	exit(0);
}

