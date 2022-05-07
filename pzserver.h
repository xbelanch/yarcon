// Project Zomboid Related Functions
#include <stdlib.h>
#include <string.h>

// Get numbers of active players
int8_t pzserver_get_num_players(char *input)
{
    char *num = malloc(sizeof(char) * 2);
    char *ptr = strchr(input, '(');
    while (*ptr != ')') {
            *num++ = *ptr++;
        }
    return atoi(num);
}