
CFLAGS+= -Wall -DDEBUG -g -O2
CFLAGS+=  -Wextra -Wcast-qual -Wcast-align -Wshadow -Wstrict-aliasing=1 -Wswitch-enum -Wdeclaration-after-statement -Wstrict-prototypes -Wundef
CXXFLAGS+= -std=c++11 

OBJDIR=objs

M ?= ${.CURDIR}
INCDIRS = -I$(M)/../$(OBJDIR)/include_e -DEMULATE_SYSCTL
INCDIRS += -I$(M)/../kipfw/sys -I$(M)/../kipfw/extra/sys -I$(M)/../kipfw/extra/sys/contrib/pf






