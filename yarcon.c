// Storage Size of addrinfo isn't known: https://stackoverflow.com/questions/37541985/storage-size-of-addrinfo-isnt-known
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>     // read, write, close
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr
#include <sys/socket.h> // socket, connect
#include <netdb.h>      // struct hostent, gethostbyname
#include <arpa/inet.h>  // get IP addresses from sockaddr

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

int parse_input_file(GameServer *gameserver, char *input)
{
    FILE *fp = fopen(input, "rb");
    if (NULL == fp) {
        fprintf(stderr, "[!] Cannot open file %s\n", input);
        exit(1);
    }

    char **lines = (char **) malloc(sizeof(char) * MAX_LINES_SIZE);
    char s[MAX_LINE_SIZE];
    size_t size_lines_len = 0;
    while (fgets(s, MAX_LINE_SIZE, fp)) {
        lines[size_lines_len] = (char *) malloc(sizeof(char) * (strlen(s) - 1));
        memcpy(lines[size_lines_len], s, strlen(s) - 1);
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

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv[0];

    char buffer[256];
    memset(buffer, '\0', 256);

    // 0. Display some info
    puts("yarcon " VERSION);

    // 1. Parse input data from file
    GameServer gameserver = { 0 };
    parse_input_file(&gameserver, argv[1]);
    fprintf(stdout, "[i] Game server: %s\n", gameserver.game);

    // 2. Populate auth packet
    Pckt_Src_Struct pckt = {
        .size = 4 + 4 + strlen(gameserver.password) + 2,
        .id = abs(rand()),
        .type = SERVERDATA_AUTH,
        .len = 4 + 4 + 4 + strlen(gameserver.password) + 2
    };
    memcpy(&pckt.body, gameserver.password, strlen(gameserver.password));

    // 3. Serialize data
    yarcon_serialize_data(&pckt, buffer);

    // 4. Connect to remote host
    int sck;

    struct addrinfo *result, *p = NULL;
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = 0,
        .ai_protocol = 0
    };
    {
        /* IPv4 */
        char ipv4[INET_ADDRSTRLEN];
        struct sockaddr_in *addr4;

        int ret = getaddrinfo(gameserver.host, gameserver.port, &hints, &result);
        if (ret != 0) {
            fprintf(stderr, "\033[01;31mError\033[0m: getaddrinfo: %s\n", gai_strerror(ret));
            exit(1);
        } else {
            addr4 = (struct sockaddr_in *) result->ai_addr;
            inet_ntop(AF_INET, &addr4->sin_addr, ipv4, INET_ADDRSTRLEN);
            fprintf(stdout, "\033[0;32mIP connect\033[0m: %s\n", ipv4);
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

        fprintf(stdout, "[i] \033[01;33mConnected successful!\033[0m (%s:%s)\n", gameserver.host, gameserver.port);
        freeaddrinfo(result);
    }

    // 5. Auth
    {
        int ret = send(sck, buffer, pckt.len, 0);
        if (ret == -1) {
            perror("[!] \033[01;31mError\033[0m: failed to send packet");
            return (-1);
        }

        char recv_buffer[512];
        memset(recv_buffer, 0, 512);
        ret = recv(sck, recv_buffer, 512, 0);
    }

    // 6. Send and execute command
    // Send message to Project Zomboid Server
    char *cmd = "players";
    // body = "servermsg \"Server will restart in 5 minutes\"";
    // Send message to Rust Legacy Server
    // body = "notice.popupall \"Server will restart in 5 minutes\"";
    // body = "find *";
    pckt = (Pckt_Src_Struct){
        .size = 4 + 4 + strlen(cmd) + 2,
        .id = abs(rand()),
        .type = SERVERDATA_EXECCOMMAND,
        .len = 4 + 4 + 4 + strlen(cmd) + 2
    };
    {
        // Populate packet
        memset(buffer, 0, sizeof(buffer));
        memcpy(&pckt.body, cmd, strlen(cmd));

        // 6.1. Serialize data
        yarcon_serialize_data(&pckt, buffer);

        // 6.2 Send
        int ret = send(sck, buffer, pckt.len, 0);
        if (ret == -1) {
            perror("[!] \033[01;31mError\033[0m: failed to send packet");
            return (-1);
        }

        // 6.3 Recieve
        char recv_buffer[MAX_BUFFER_SIZE];
        memset(recv_buffer, 0, MAX_BUFFER_SIZE);
        ret = recv(sck, recv_buffer, MAX_BUFFER_SIZE, 0);
        Pckt_Src_Struct *res = (Pckt_Src_Struct *)recv_buffer;
        printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);

        // 6.4 Deserialize data from server if auth response is ok
        // TODO: handle multiple-packet responses
        if (res->id > 0) {
            memset(recv_buffer, 0, MAX_BUFFER_SIZE);
            ret = recv(sck, recv_buffer, MAX_BUFFER_SIZE, 0);
            res = (Pckt_Src_Struct *)recv_buffer;
            printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);
        } else {
            memset(recv_buffer, 0, MAX_BUFFER_SIZE);
            ret = recv(sck, recv_buffer, MAX_BUFFER_SIZE, 0);
            res = (Pckt_Src_Struct *)recv_buffer;
            printf("res->id: %u Something went wrong. Maybe password is not set properly.\n", res->id);
        }
    }

    return (0);
}