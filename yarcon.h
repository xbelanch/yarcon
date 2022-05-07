#ifndef YARCON_H
#define YARCON_H

#include "color_utils.h"

#define PROGRAM_NAME "yarcon"
#define VERSION "0.1.0"
#define MAX_BUFFER_SIZE 4096
#define MAX_LINES_SIZE 128
#define MAX_LINE_SIZE 64

typedef enum
{
    SERVERDATA_RESPONSE_VALUE = 0,
    SERVERDATA_AUTH_RESPONSE = 2,
    SERVERDATA_EXECCOMMAND = 2,
    SERVERDATA_AUTH = 3,
} PacketSourceType;

typedef struct
{
    char game[32];
    char host[32];
    char port[16];
    char password[128];
} GameServer;

// Their payload follows the following basic structure:
// You can find out more information at
typedef struct packet_source_struct
{
    int32_t size; // 4 bytes
    int32_t id; // 4 bytes
    PacketSourceType type; // 1 byte
    char body[MAX_BUFFER_SIZE]; // len of body
    size_t len;
} Pckt_Src_Struct;


int serialize_int32_t(int32_t val, char *buffer)
{
    // val = htonl(val);
    memcpy(buffer, &val, sizeof(int32_t));
    return (0);
}

int yarcon_serialize_data(Pckt_Src_Struct *pckt, char *buffer)
{
    char *ptr = buffer;
    serialize_int32_t(pckt->size, ptr);
    ptr += sizeof(int32_t);
    serialize_int32_t(pckt->id, ptr);
    ptr += sizeof(int32_t);
    serialize_int32_t(pckt->type, ptr);
    ptr += sizeof(int32_t);
    memcpy(ptr, pckt->body, strlen(pckt->body));

    return (0);
}

void yarcon_populate_source_packet(Pckt_Src_Struct *pckt, PacketSourceType type, char *body)
{
    pckt->size = 4 + 4 + strlen(body) + 2;
    pckt->id = abs(rand());
    pckt->type = type;
    pckt->len = 4 + 4 + 4 + strlen(body) + 2;
    memcpy(pckt->body, body, strlen(body));
}

int yarcon_send_packet(int sck, char *buffer, size_t len)
{
    int ret = send(sck, buffer, len, 0);
    if (ret == -1) {
        perror("[!] \033[01;31mError\033[0m: failed to send packet");
        return (-1);
    }

    return (0);
}

int yarcon_receive_response(int sck, char *buffer, size_t buffer_len)
{
    int ret = recv(sck, buffer, buffer_len, 0);
    return (ret);
}


int yarcon_connect_gamserver(char *host, char *port)
{
    int sck;
    struct addrinfo *result, *p = NULL;
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = 0,
        .ai_protocol = 0
    };

    /* IPv4 */
    char ipv4[INET_ADDRSTRLEN];
    struct sockaddr_in *addr4;

    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "\033[01;31mError\033[0m: getaddrinfo: %s\n", gai_strerror(ret));
        exit(1);
    } else {
        addr4 = (struct sockaddr_in *) result->ai_addr;
        inet_ntop(AF_INET, &addr4->sin_addr, ipv4, INET_ADDRSTRLEN);
        fprintf(stdout, BGREEN "[i] " RESET "IP connect: " BYELLOW "%s\n" RESET, ipv4);
    }

    p = result;
    sck = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sck < 0) {
        perror("\033[01;31mError\033[0m: Cannot create socket\n");
        exit(1);
    } else {
        if (connect(sck, p->ai_addr, p->ai_addrlen) < 0) {
            perror("\033[01;31mError\033[0m: Cannot connect\n");
            close(sck);
            freeaddrinfo(result);
            exit(1);
        }
        if (p == NULL || sck < 0) {
            perror("\033[01;31mError\033[0m: Connection failed\n");
            freeaddrinfo(result);
            exit(1);
        }
    }

    fprintf(stdout, BGREEN "[i] " RESET "Connected successful! " BYELLOW "(%s:%s)\n" RESET, host, port);
    freeaddrinfo(result);

    return (sck);
}

int yarcon_parse_input_file(GameServer *gameserver, char *input)
{
    FILE *fp = fopen(input, "rb");
    if (NULL == fp) {
        fprintf(stderr, "[!] Cannot open file %s\n", input);
        exit(1);
    }

    char **lines = (char **) malloc(sizeof(char) * MAX_LINES_SIZE);
    char *entry = malloc(sizeof(char) * MAX_LINE_SIZE);
    memset(entry, 0, MAX_LINE_SIZE);
    char *s = malloc(sizeof(char) * MAX_LINE_SIZE);
    size_t size_lines_len = 0;
    while (fgets(s, MAX_LINE_SIZE, fp)) {

        // Clean one or more spaces
        char *d = s;
        char *ptr = entry;
        while (*d != '\0') {
            if (*d == ' ') {
                ++d;
            } else {
                *entry++ = *d++;
            }
        }

        entry = ptr;

        lines[size_lines_len] = (char *) malloc(sizeof(char) * strlen(entry) - 1);
        memcpy(lines[size_lines_len], entry, strlen(entry) - 1);
        memset(entry, 0, MAX_LINE_SIZE);
        size_lines_len++;
    }

    // Parser input data
    for (size_t i = 0; i < size_lines_len; ++i) {
        char *ptr_start = lines[i];
        char *ptr_end = strchr(lines[i], ':');
        size_t len = ptr_end - ptr_start;
        char *field = malloc(sizeof(char) * len);
        memset(field, 0, len);
        memcpy(field, lines[i], len);

        char *value = ptr_end + 1;
        if (!strcmp("game", field)) {
            memcpy(gameserver->game, value, strlen(value));
        } else if (!strcmp("host", field)) {
            memcpy(gameserver->host, value, strlen(value));
        } else if (!strcmp("port", field)) {
            memcpy(gameserver->port, value, strlen(value));
        } else if (!strcmp("password", field)) {
            memcpy(gameserver->password, value, strlen(value));
        }
    }

    fclose(fp);
    return (0);
}

#endif // YARCON_H