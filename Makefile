d = 0
CC = gcc
ifeq ($(d), 1)
CFLAGS = -g -Wall -Ddebug
else
CFLAGS = -g -Wall
endif

all: client

client:client.o rudp.o event.o
	$(CC) $(CFLAGS) $^ -o $@

client.o rudp.o: rudp.h rudp_api.h event.h

event.c: event.h

clean:
	/bin/rm -f   *.o client server
