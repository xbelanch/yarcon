// Project Zomboid Related Functions
#include <stdlib.h>
#include <string.h>

// Get numbers of active players
int8_t pzserver_get_num_players(char *input)
{
    char *num = malloc(sizeof(char) * 2);
    char *ptr_num = num;
    memset(num, 0, 2);
    char *ptr = strchr(input, '(');
    ptr++; // avoid '('
    while (*ptr != ')') {
        *num++ = *ptr++;
    }
    *num = '\0';
    num = ptr_num;
    return atoi(num);
}
