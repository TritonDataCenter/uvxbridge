
CFLAGS= -Wall -std=c++11

main.o: main.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c main.cpp
cmddispatch.o: cmddispatch.cpp uvxbridge.h
	$(CXX) $(CFLAGS) -c cmddispatch.cpp

dispatch_test: main.o cmddispatch.o
	$(CXX) main.o cmddispatch.o -o dispatch_test


all: dispatch_test
