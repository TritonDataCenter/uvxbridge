
CFLAGS+= -Wall -DDEBUG
CFLAGS+=  -Wextra -Wcast-qual -Wcast-align -Wshadow -Wstrict-aliasing=1 -Wswitch-enum -Wdeclaration-after-statement -Wstrict-prototypes -Wundef
CXXFLAGS+= $(CFLAGS)
CXXFLAGS+= -std=c++11 

OBJDIR=objs





