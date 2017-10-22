.include "../Makefile.inc"

PROG_CXX=uvxbridge
SRCS=main.cpp dispatch.cpp datapath.c uvxlan.cpp xxhash.c config.cpp
LDADD= -L../kipfw -lkipfw
LDFLAGS+=-pthread 
CFLAGS+= -include ${.CURDIR}/../kipfw/extra/glue.h
CFLAGS+= -DUSERSPACE
CFLAGS+= -I${.CURDIR}/../kipfw/extra
MAN=

.include <bsd.prog.mk>
