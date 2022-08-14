CC = gcc
CFLAGS = -Wall -pedantic -Wshadow -std=c99

.DEFAULT: all
.PHONY: all clean

all: RUSHBSvr

RUSHBSvr: RUSHBSvr.c session_tree.c RUSHBSvr.h
	$(CC) $(CFLAGS) -pthread -g session_tree.c RUSHBSvr.c -o RUSHBSvr

clean:
	rm -f *.o

