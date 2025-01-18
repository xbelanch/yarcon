#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> // remove warning Implicit declaration of function ‘read’ and ‘write’
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

static void cleanup(void)
{
    // @TODO: To be done (07-09-2022)
    // config_free();
    // src_rcon_free(r);
    // free(host);
    // free(password);
    // free(port);
    // free(config);
    // free(server);

    // if (response) {
    //     g_byte_array_free(response, TRUE);
    // }
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv[0];
    printf("YARCON is still alive\n");

    atexit(cleanup);

    // Create first auth packet
    Packet auth = { .Size = 0, .ID = 255, .Type = SERVERDATA_AUTH, .body = "hegelmarxzizek", .null = 0x0 };
    // Calculate packet size
    auth.Size = strlen(auth.body) + 10;
    // Add empty string
    auth.body[strlen(auth.body) + 1] = 0x00;

    // Socket vars
    int fd, ret;

    // Connect with the server
    {
        short port = 16261;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("93.176.181.245");
        // addr.sin_addr.s_addr = inet_addr("172.18.0.2");

        fd = socket(AF_INET, SOCK_STREAM, 0);
        exit_if(fd<0, "Create socket error");

        ret = connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr));
        exit_if(ret<0, "Connect to server error");

        printf("Connect to server success\n");
    }

    // Serialize using open_memstream and fwrite
    FILE *str;
    char *buf;
    size_t len;
    {
        str = open_memstream(&buf, &len);
        exit_if(str == NULL, "Cannot create stream");
        fwrite(&auth.Size, 1, sizeof(auth.Size), str);
        fwrite(&auth.ID, 1, sizeof(auth.ID), str);
        fwrite(&auth.Type, 1, sizeof(auth.Type), str);
        fwrite(&auth.body, 1, strlen(auth.body), str);
        fwrite(&auth.null, 1, sizeof(char), str);
        fwrite(&auth.null, 1, sizeof(char), str);
        fclose(str);
    }

    // Write socket and send request auth first
    {
        char *ptr = buf;
        size_t size = len;
        do {
            ret = write(fd, ptr, size);
            exit_if(ret < 0 || ret == 0, "Cannot send packet\n");
            ptr += ret;
            size -= ret;
        } while (size > 0);
    }
    exit(0);

    // wait auth packet
    uint8_t tmp[512];
    ret = read(fd, tmp, sizeof(tmp));
    printf("ret: %d\n", ret);
    exit_if(ret < 0, "Cannot send packet to server\n");
    // @TODO: Parse auth response (09-09-2022)

    // Send command to server
    Packet command = { .Size = 0, .ID = 255, .Type = SERVERDATA_EXECCOMMAND, .body = "players", .null = 0x0 };
    // Calculate packet size
    command.Size = strlen(command.body) + 10;
    // Add empty string
    command.body[strlen(command.body) + 1] = 0x00;

    buf = NULL;
    free(NULL);

    len = 0;
    str = open_memstream(&buf, &len);
    exit_if(str == NULL, "Cannot create stream");
    fwrite(&command.Size, 1, sizeof(command.Size), str);
    fwrite(&command.ID, 1, sizeof(command.ID), str);
    fwrite(&command.Type, 1, sizeof(command.Type), str);
    fwrite(&command.body, 1, strlen(command.body), str);
    fwrite(&command.null, 1, sizeof(char), str);
    fwrite(&command.null, 1, sizeof(char), str);
    fclose(str);

    ret = write(fd, buf, len);
    printf("ret: %d\n", ret);
    exit_if(ret < 0, "Cannot send packet to server\n");

    // wait command response 1
    uint8_t tmp2[512];
    ret = read(fd, tmp2, sizeof(tmp2));
    printf("ret: %d\n", ret);
    exit_if(ret < 0, "Cannot recieve packet from server\n");
    // @TODO: Parse command response

    uint8_t tmp3[512];
    ret = read(fd, tmp3, sizeof(tmp3));
    printf("ret: %d\n", ret);
    exit_if(ret < 0, "Cannot recieve packet from server\n");
    // @TODO: Parse command response


cleanup:
    // free(auth.body);
    // if (fd > -1)
    //     close(fd);
    printf("cleanup\n");

    return (0);
}
