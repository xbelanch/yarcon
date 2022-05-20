#!/bin/sh

set -xe

CC="/usr/bin/gcc"
CFLAGS="-Wall -Wextra -std=c99 -pedantic -ggdb"
SRC="yarcon.c"

$CC $CFLAGS -o yarcon $SRC
