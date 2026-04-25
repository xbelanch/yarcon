#ifndef GAME_RESPONSE_H
#define GAME_RESPONSE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Extract a small non-negative integer between two delimiters in a server response.
// This is intentionally game-agnostic; callers decide whether "(12)", "[12]",
// or another response shape has useful meaning for a specific command.
static int8_t game_response_extract_int_between(const char *input, char open, char close)
{
    const char *begin;
    const char *end;
    char num[4] = { 0 };
    size_t len;
    long parsed;

    if (input == NULL) {
        return -1;
    }

    begin = strchr(input, open);
    if (begin == NULL) {
        return -1;
    }

    begin++;
    end = strchr(begin, close);
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

#endif // GAME_RESPONSE_H
