# makefile for AoEde

# see README for others
PLATFORM=linux

prefix = /usr
sbindir = ${prefix}/sbin
sharedir = ${prefix}/share
mandir = ${sharedir}/man
libdir=${prefix}/lib
includedir=${prefix}/include

O=tagring.o bfdio.o aoe.o bpf.o ${PLATFORM}.o ata.o dat.o
CFLAGS += -Wall -g -O2 -I${includedir}
CC = gcc
L=

ifeq ($(PLATFORM), linux)
    L += -laio
endif

aoede: $O
	${CC} -o aoede $O $L

dat.o : dat.c config.h dat.h 
	${CC} ${CFLAGS} -c $<

aoe.o : aoe.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

tagring.o : tagring.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

bfdio.o : bfdio.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

${PLATFORM}.o : ${PLATFORM}.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

ata.o : ata.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

bpf.o : bpf.c
	${CC} ${CFLAGS} -c $<

config.h : config/config.h.in makefile
	@if ${CC} ${CFLAGS} config/u64.c > /dev/null 2>&1; then \
	  sh -xc "cp config/config.h.in config.h"; \
	else \
	  sh -xc "sed 's!^//u64 !!' config/config.h.in > config.h"; \
	fi

clean :
	rm -f $O aoede

install : aoede aoeded
	install aoede ${sbindir}/
	install aoeded ${sbindir}/
	install aoede.8 ${mandir}/man8/

