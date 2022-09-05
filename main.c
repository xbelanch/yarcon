#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#define exit_if(r, ...)                                                                          \
    if (r) {                                                                                     \
        printf(__VA_ARGS__);                                                                     \
        printf("%s:%d error no: %d error msg %s\n", __FILE__, __LINE__, errno, strerror(errno)); \
        exit(1);                                                                                 \
    }

#define  MAX_BUFFER_SIZE 1024

typedef enum source_packet_type
{
    SERVERDATA_RESPONSE_VALUE = 0,
    SERVERDATA_AUTH_RESPONSE = 2,
    SERVERDATA_EXECCOMMAND = 2,
    SERVERDATA_AUTH = 3,
} PacketType;

typedef struct
{
    int32_t Size; // 4 bytes
    int32_t ID; // 4 bytes
    PacketType Type; // 1 byte
    char body[MAX_BUFFER_SIZE]; // body
    char null;
} Packet;


int serialize_int32(int32_t val, char *buffer)
{
    memcpy(buffer, &val, sizeof(int32_t));
    return (0);
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv[0];
    printf("YARCON is still alive\n");

    // Create first auth packet
    Packet auth = { .Size = 0, .ID = 0, .Type = SERVERDATA_AUTH, .body = "hegelmarxzizek", .null = 0x0 };
    // Calculate packet size
    auth.Size = strlen(auth.body) + 10;
    // Add empty string
    auth.body[strlen(auth.body) + 1] = 0x00;

    // Connect with the server
    short port = 16261;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("93.176.181.245");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    exit_if(fd<0, "Create socket error");

    int ret = connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr));
    exit_if(ret<0, "Connect to server error");

    printf("Connect to server success\n");

    // Serialize using open_memstream and fwrite
    FILE *str;
    char *buf;
    size_t len;
    str = open_memstream(&buf, &len);
    exit_if(str == NULL, "Cannot create stream");
    fwrite(&auth.Size, 1, sizeof(auth.Size), str);
    fwrite(&auth.ID, 1, sizeof(auth.ID), str);
    fwrite(&auth.Type, 1, sizeof(auth.Type), str);
    fwrite(&auth.body, 1, strlen(auth.body), str);
    fwrite(&auth.null, 1, sizeof(char), str);
    fwrite(&auth.null, 1, sizeof(char), str);
    fclose(str);

    // Send auth packet to server
    ret = send(fd, buf, len, 0);
    exit_if(ret < 0, "Cannot send packet to server\n");

    return (0);
}
