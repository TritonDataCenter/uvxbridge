.include "../Makefile.inc"

SRCS=main.cpp dispatch.cpp datapath.c uvxlan.cpp xxhash.c config.cpp
LDFLAGS+=-pthread -L${.CURDIR}/../kipfw -lkipfw
PROG_CXX=uvxbridge
MAN=

.include <bsd.prog.mk>
