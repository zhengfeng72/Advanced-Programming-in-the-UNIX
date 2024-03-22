#
# Makefile for apue library.
#

SYS	= $(shell uname -s)
CFLAGS	= -ansi -I../include -Wall -D_GNU_SOURCE $(EXTRA)
LDFLAGS	=

AR	= ar
LIBAPUE	= libapue.a
OBJS	=  bufargs.o cliconn.o clrfl.o \
	  daemonize.o error.o errorlog.o lockreg.o locktest.o \
	  openmax.o pathalloc.o popen.o prexit.o prmask.o \
	  ptyfork.o readn.o recvfd.o \
	  senderr.o sendfd.o servaccept.o servlisten.o \
	  setfl.o signal.o signalintr.o \
	  sleep.o sleepus.o spipe.o \
	  tellwait.o ttymodes.o writen.o # pathconf.o sysconf.o strerror.o 

ifeq ($(SYS),FreeBSD)
CFLAGS	+= -D__BSD_VISIBLE
OBJS	+= bsd_ptyopen.o
endif

ifeq ($(SYS),Linux)
CFLAGS	+= -DLINUX
OBJS	+= linux_ptyopen.o
endif

RANLIB	= ranlib

all: $(OBJS)
	$(AR) rc $(LIBAPUE) $?
	$(RANLIB) $(LIBAPUE)

.c.o:
	gcc -c $(CFLAGS) $<

ptyopen.c: linux_ptyopen.c
	cp linux_ptyopen.c ptyopen.c

clean:
	rm -f *.o a.out core temp.* ptyopen.c $(LIBAPUE)

