.include "../Makefile.inc"

SRCS=main.cpp dispatch.cpp datapath.c uvxlan.cpp xxhash.c
LDFLAGS+=-pthread -L../ipfw -lipfw
PROG_CXX=uvxbridge
MAN=

.include <bsd.prog.mk>
