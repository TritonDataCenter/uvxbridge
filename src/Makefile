.include "../Makefile.inc"

default: all

OBJDIR=objs

uvxbridge: main.o dispatch.o datapath.o uvxlan.o xxhash.o
	$(CXX) main.o dispatch.o datapath.o uvxlan.o xxhash.o -pthread -o uvxbridge

all: uvxbridge

clean:
	rm -f uvxbridge *.o *~ *.core
