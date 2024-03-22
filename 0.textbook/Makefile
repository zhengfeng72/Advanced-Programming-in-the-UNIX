
# note: build order dependency: ch14 -> ch13

SYS	= $(shell uname -s)
MAKE	= make
ifeq ($(SYS),FreeBSD)
MAKE	= gmake
endif

DIRS	= lib \
	  ch1  ch2  ch3  ch4  ch5  ch6  ch7  ch8  ch9  ch10 \
	  ch11 ch12 ch14 ch13 ch15 ch16 ch17 ch18 ch19 ch20

all:
	(for X in $(DIRS); do $(MAKE) -C $$X all || return 1 ; done)

cleanobj:
	(for X in $(DIRS); do $(MAKE) -C $$X cleanobj ; done)

clean:
	(for X in $(DIRS); do $(MAKE) -C $$X clean ; done)

