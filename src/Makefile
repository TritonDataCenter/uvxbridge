default: all

CFLAGS= -Wall -std=c++11 -DDEBUG

main.o: main.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c main.cpp
cmddispatch.o: cmddispatch.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c cmddispatch.cpp
datapath.o: datapath.cpp uvxbridge.h uvxlan.h
	$(CXX) $(CFLAGS) -c datapath.cpp
uvxlan.o: uvxlan.cpp uvxbridge.h uvxlan.h
	$(CXX) $(CFLAGS) -c uvxlan.cpp

uvxbridge: main.o cmddispatch.o datapath.o uvxlan.o
	$(CXX) main.o cmddispatch.o datapath.o uvxlan.o -o uvxbridge


all: uvxbridge

clean:
	rm -f uvxbridge *.o *~
