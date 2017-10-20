.if defined(VERBOSE)
MSG=@echo
HIDE=@
.else
MSG=@\#
HIDE=
.endif


CFLAGS:= -Wall -DDEBUG
CFLAGS+=  -Wextra -Wcast-qual -Wcast-align -Wshadow -Wstrict-aliasing=1 -Wswitch-enum -Wdeclaration-after-statement -Wstrict-prototypes -Wundef
CXXFLAGS:= $(CFLAGS)
CXXFLAGS+= -std=c++11 

.cpp.o:
	$(MSG) "   CC $<"
	$(HIDE) $(CXX) $(CXXFLAGS) -c $< -o $@

.c.o:
	$(MSG) "   CC $<"
	$(HIDE) $(CC) $(CFLAGS) -c $< -o $@


