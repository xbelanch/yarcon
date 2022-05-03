CC=gcc
CFLAGS=-Wall -Wextra -std=c11 -pedantic -ggdb
LIBS=
INPUT=

.PHONY: all
all: yarcon

yarcon: yarcon.c
	$(CC) $(CFLAGS) -o yarcon yarcon.c $(LIBS)