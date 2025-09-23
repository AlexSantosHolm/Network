
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g

all: mipd ping_client ping_server

mipd: mipd.c mip.h
	$(CC) $(CFLAGS) -o mipd mipd.c

ping_client: ping_client.c mip.h
	$(CC) $(CFLAGS) -o ping_client ping_client.c

ping_server: ping_server.c mip.h
	$(CC) $(CFLAGS) -o ping_server ping_server.c

clean:
	rm -f mipd ping_client ping_server *.o *.socket

.PHONY: all clean
