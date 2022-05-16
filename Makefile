CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -pedantic -ggdb
DIRECTIVES=-DSOURCE
LIBS=
INPUT=

.PHONY: all
all: yarcon

yarcon: yarcon.c
	$(CC) $(CFLAGS) $(DIRECTIVES) -o yarcon yarcon.c $(LIBS)