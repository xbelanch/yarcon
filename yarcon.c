// Storage Size of addrinfo isn't known: https://stackoverflow.com/questions/37541985/storage-size-of-addrinfo-isnt-known
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>     // read, write, close
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr
#include <sys/socket.h> // socket, connect
#include <netdb.h>      // struct hostent, gethostbyname
#include <arpa/inet.h>  // get IP addresses from sockaddr

#define VERSION "0.1.0"
#define MAX_BUFFER_SIZE 4096

typedef enum
{
    SERVERDATA_RESPONSE_VALUE = 0,
    SERVERDATA_AUTH_RESPONSE = 2,
    SERVERDATA_EXECCOMMAND = 2,
    SERVERDATA_AUTH = 3,
} PacketSourceType;

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

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv[0];

    char buffer[256];
    memset(buffer, '\0', 256);
    char *body = "password";

    // Display some info
    puts("yarcon " VERSION);

    // Populate packet
    Pckt_Src_Struct pckt = {
        .size = 4 + 4 + strlen(body) + 2,
        .id = abs(rand()),
        .type = SERVERDATA_AUTH,
        .len = 4 + 4 + 4 + strlen(body) + 2
    };
    memcpy(&pckt.body, body, strlen(body));

    // 0. Serialize data
    yarcon_serialize_data(&pckt, buffer);

    // 1. Connect to remote host
    int sck;

    // Change these values to fit your needs
    const char *host = "192.168.1.11";
    const char *port = "29016";

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

        int ret = getaddrinfo(host, port, &hints, &result);
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

        fprintf(stdout, "[i] \033[01;33mConnected successful!\033[0m (%s:%s)\n", host, port);
        freeaddrinfo(result);
    }

    // 2. Auth
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

    // 3. Send and execute command
    // Send message to Project Zomboid Server
    // body = "servermsg \"Server will restart in 5 minutes\"";
    // Send message to Rust Legacy Server
    // body = "notice.popupall \"Server will restart in 5 minutes\"";
    body = "find *";
    pckt = (Pckt_Src_Struct){
        .size = 4 + 4 + strlen(body) + 2,
        .id = abs(rand()),
        .type = SERVERDATA_EXECCOMMAND,
        .len = 4 + 4 + 4 + strlen(body) + 2
    };
    {
        // Populate packet
        memset(buffer, 0, sizeof(buffer));
        memcpy(&pckt.body, body, strlen(body));

        // 3.1. Serialize data
        yarcon_serialize_data(&pckt, buffer);

        // 3.2 Send
        int ret = send(sck, buffer, pckt.len, 0);
        if (ret == -1) {
            perror("[!] \033[01;31mError\033[0m: failed to send packet");
            return (-1);
        }

        // 3.3 Recieve
        char recv_buffer[MAX_BUFFER_SIZE];
        memset(recv_buffer, 0, MAX_BUFFER_SIZE);
        ret = recv(sck, recv_buffer, MAX_BUFFER_SIZE, 0);
        Pckt_Src_Struct *res = (Pckt_Src_Struct *)recv_buffer;
        printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);

        // 3.4 Deserialize data from server if auth response is ok
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