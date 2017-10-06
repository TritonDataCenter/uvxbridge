default: all

CFLAGS= -Wall -std=c++11 -DDEBUG

main.o: main.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c main.cpp
cmddispatch.o: cmddispatch.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c cmddispatch.cpp
datapath.o: datapath.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c datapath.cpp

dispatch_test: main.o cmddispatch.o datapath.o
	$(CXX) main.o cmddispatch.o -o dispatch_test


all: dispatch_test

clean:
	rm -f dispatch_test *.o *~
