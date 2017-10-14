default: all

CFLAGS= -Wall -DDEBUG
CFLAGS+=  -Wextra -Wcast-qual -Wcast-align -Wshadow -Wstrict-aliasing=1 -Wswitch-enum -Wdeclaration-after-statement -Wstrict-prototypes -Wundef
CXXFLAGS= $(CFLAGS)
CXXFLAGS+= -std=c++11 

main.o: main.cpp uvxbridge.h
	$(CXX) $(CXXFLAGS) -c main.cpp
cmddispatch.o: cmddispatch.cpp uvxbridge.h
	$(CXX) $(CXXFLAGS) -c cmddispatch.cpp
datapath.o: datapath.c uvxbridge.h uvxlan.h
	$(CC) $(CFLAGS) -c datapath.c
uvxlan.o: uvxlan.cpp uvxbridge.h uvxlan.h
	$(CXX) $(CXXFLAGS) -c uvxlan.cpp

xxhash.o: xxhash.c xxhash.h
	$(CC) $(CFLAGS) -c xxhash.c

uvxbridge: main.o cmddispatch.o datapath.o uvxlan.o xxhash.o
	$(CXX) main.o cmddispatch.o datapath.o uvxlan.o xxhash.o -o uvxbridge


all: uvxbridge

clean:
	rm -f uvxbridge *.o *~
