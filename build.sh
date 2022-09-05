#!/bin/bash

set -xe
out="yarcon"
cc="/usr/bin/gcc"
cflags="-Wall -Wextra -std=gnu11 -pedantic -ggdb"
libs=
src=( $(ls *.c) )
$cc $cflags -c ${src[*]}
objs=( $(ls *.o) )
$cc ${objs[*]} $libs -o $out
rm ${objs[*]}
set +xe
