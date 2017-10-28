.include "../Makefile.inc"

PROG_CXX=uvxbridge
SRCS=main.cpp dispatch.cpp uvxlan.cpp xxhash.c config.cpp dtls.cpp \
	uvxcommand.cpp
LDADD= -L../kipfw -lkipfw -L/usr/local/lib -lbotan-2 \
	-L${.CURDIR}/../common -lnmutil
LDFLAGS+=-pthread 
CFLAGS+= -DUSERSPACE -DINET -D_BSD_SOURCE -D_DEFAULT_SOURCE $(INCDIRS)
CFLAGS+= -I${.CURDIR}/../kipfw/extra -I/usr/local/include/botan-2
CFLAGS+= -I${.CURDIR}/../common
MAN=

.include <bsd.prog.mk>
