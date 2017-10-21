.if defined(VERBOSE)
MSG=@echo
HIDE=@
.else
MSG=@\#
HIDE=
.endif

OBJDIR=objs

CFLAGS:= -Wall -DDEBUG
CFLAGS+=  -Wextra -Wcast-qual -Wcast-align -Wshadow -Wstrict-aliasing=1 -Wswitch-enum -Wdeclaration-after-statement -Wstrict-prototypes -Wundef
CXXFLAGS:= $(CFLAGS)
CXXFLAGS+= -std=c++11 

INCDIRS += -I ../$(OBJDIR)/include_e -DEMULATE_SYSCTL
INCDIRS += -I../ipfw/sys -I../ipfw/extra/sys -I../ipfw/extra/sys/contrib/pf

.cpp.o:
	$(MSG) "   CC $<"
	$(HIDE) $(CXX) $(CXXFLAGS) -c $< -o $@

.c.o:
	$(MSG) "   CC $<"
	$(HIDE) $(CC) $(CFLAGS) -c $< -o $@


