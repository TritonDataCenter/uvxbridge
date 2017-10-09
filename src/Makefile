default: all

CFLAGS= -Wall -DDEBUG
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

uvxbridge: main.o cmddispatch.o datapath.o uvxlan.o
	$(CXX) main.o cmddispatch.o datapath.o uvxlan.o -o uvxbridge


all: uvxbridge

clean:
	rm -f uvxbridge *.o *~
