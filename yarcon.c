#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

    char buffer[128];
    memset(buffer, 0, 128);
    char *body = "password";
    Pckt_Src_Struct pckt = {
        .size = 4 + 4 + strlen(body) + 1,
        .id = abs(rand()),
        .type = SERVERDATA_AUTH,
        .body = "\0",
        .len = 4 + 4 + 4 + strlen(body) + 1
    };
    memcpy(&pckt.body, body, strlen(body));

    yarcon_serialize_data(&pckt, buffer);


    puts("yarcon " VERSION);

    return (0);
}