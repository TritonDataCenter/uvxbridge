.include "../Makefile.inc"

PROG_CXX=uvxbridge
SRCS=main.cpp dispatch.cpp datapath.c uvxlan.cpp xxhash.c config.cpp
LDADD= -L../kipfw -lkipfw
LDFLAGS+=-pthread 
CFLAGS+= -DUSERSPACE -DINET -D_BSD_SOURCE -D_DEFAULT_SOURCE $(INCDIRS)
CFLAGS+= -I${.CURDIR}/../kipfw/extra
CFLAGS+= -include ${.CURDIR}/../kipfw/extra/glue.h
MAN=

.include <bsd.prog.mk>
