.include "../Makefile.inc"

SRCS=main.cpp dispatch.cpp datapath.c uvxlan.cpp xxhash.c config.cpp
LDFLAGS+=-pthread -L${.CURDIR}/../kipfw -lkipfw
CFLAGS+= -include ${.CURDIR}/../kipfw/extra/glue.h
CFLAGS+= -DUSERSPACE
CFLAGS+= -I${.CURDIR}/../kipfw/extra
PROG_CXX=uvxbridge
MAN=

.include <bsd.prog.mk>
