#ifndef PZSERVER_H
#define PZSERVER_H

// Project Zomboid Related Functions
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Extract the active player count from Project Zomboid's "players" output.
// Expected fragment: "... (12)"; invalid or oversized values return -1.
static int8_t pzserver_get_num_players(const char *input)
{
    const char *begin;
    const char *end;
    char num[4] = { 0 };
    size_t len;
    long parsed;

    if (input == NULL) {
        return -1;
    }

    begin = strchr(input, '(');
    if (begin == NULL) {
        return -1;
    }

    begin++;
    end = strchr(begin, ')');
    if (end == NULL) {
        return -1;
    }

    len = (size_t) (end - begin);
    if (len == 0 || len >= sizeof(num)) {
        return -1;
    }

    memcpy(num, begin, len);
    parsed = strtol(num, NULL, 10);
    if (parsed < 0 || parsed > INT8_MAX) {
        return -1;
    }

    return (int8_t) parsed;
}

#endif // PZSERVER_H
