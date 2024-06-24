CC=gcc
CFLAGS=-O3 -Wall $(shell pkg-config --cflags gtk+-3.0)
LIBS=-pthread -lssl -lcrypto $(shell pkg-config --libs gtk+-3.0)

all: server.out client.out

server.out: server.o
	$(CC) $(CFLAGS) -o server.out server.o $(LIBS)

client.out: client.o
	$(CC) $(CFLAGS) -o client.out client.o $(LIBS) 

server.o: server.c
	$(CC) $(CFLAGS) -c server.c

client.o: client.c
	$(CC) $(CFLAGS) -c client.c

.PHONY: clean
clean:
	rm -f *.o *.out

