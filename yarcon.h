#ifndef YARCON_H
#define YARCON_H

#include <stdlib.h>
#include "color_utils.h"

#define PROGRAM_NAME "yarcon"
#define VERSION "0.1.0"
#define MAX_BUFFER_SIZE 4096
#define MAX_LINES_SIZE 128
#define MAX_LINE_SIZE 64

// Globals
struct sockaddr_in si_other;
unsigned int sockaddr_len;

typedef enum rcon_protocol_implementation_type
    {
        RCON_SOURCE_PROTOCOL = 0,
        RCON_BATTLEYE_PROTOCOL = 1
    } RconProtocolType;

typedef enum source_packet_type
    {
        SERVERDATA_RESPONSE_VALUE = 0,
        SERVERDATA_AUTH_RESPONSE = 2,
        SERVERDATA_EXECCOMMAND = 2,
        SERVERDATA_AUTH = 3,
    } PacketSourceType;

typedef enum be_packet_type
    {
        BE_PACKET_LOGIN = 0x00,
        BE_PACKET_COMMAND = 0x01,
        BE_PACKET_MESSAGE = 0x02,
    } PacketBattleyeType;

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

// BE Packet Structure
// Source: https://www.battleye.com/downloads/BERConProtocol.txt
typedef struct packet_battleye_struct
{
    unsigned char start_header[2]; // 'B'(0x42) | 'E'(0x45)
    uint32_t checksum; // 4-byte CRC32 checksum of the subsequent bytes
    unsigned char payload[MAX_BUFFER_SIZE]; // 0xff + packet type + command
} Pckt_BE_Struct;

void print_help()
{
    puts(
         BGREEN "YARCON " VERSION RESET " - https://github.com/xbelanch/rcon\n"
         "Send rcon commands to game servers with rcon support.\n\n"
         "Usage: yarcon [OPTIONS] [COMMANDS]\n"
         "Options:\n"
         "  -H\t\tServer addres (default: 0.0.0.0)\n"
         "  -P\t\tPort\n"
         "  -p\t\tpassword\n"
         "  -h\t\tPrint usage\n"
         "  -v\t\tVersion\n\n"
         );

    puts ("Example:\n\tyarcon -H my.game.server -P port.server -p password -c \"status\"\n");
}


// Stolen from: https://gist.github.com/MultiMote/169265fd74fe94b44941c1b05b296f0d
uint32_t crc32(unsigned char *begin, unsigned char *end) {
   int j;
   uint32_t byte, crc, mask;
   static uint32_t table[256];
   /* Set up the table, if necessary. */
   if (table[1] == 0) {
      for (byte = 0; byte <= 255; byte++) {
         crc = byte;
         for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
         }
         table[byte] = crc;
      }
   }
   /* Through with table setup, now calculate the CRC. */
   crc = 0xFFFFFFFF;
   while (begin != end) {
      byte = *begin;
      crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF];
      ++begin;
   }
   return ~crc;
}

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

void append_str(char *src, unsigned char *dst)
{
    while (*src != '\0') {
        *dst++ = *src++;
    }
}

int yarcon_serialize_be_data(Pckt_BE_Struct *pckt, char *buffer)
{
    char *ptr = buffer;
    memcpy(ptr, pckt->start_header, sizeof(unsigned char) * 2);
    ptr += sizeof(unsigned char) * 2;
    memcpy(ptr, &pckt->checksum, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &pckt->payload, 1024);
    return (0);
}

void yarcon_populate_be_packet(Pckt_BE_Struct *pckt, PacketBattleyeType type,  char *body)
{

    // For checksum we need to populate payload first

    unsigned char payload[1024];
    memset(payload, '\0', 1024);
    unsigned char *ptr = payload;
    memset(ptr++, 0xFF, sizeof(unsigned char));
    memset(ptr++, type, sizeof(unsigned char));
    int offset = 2;
    if (type == BE_PACKET_COMMAND) {
        memset(ptr++, 0x0, sizeof(unsigned char));
        offset++;
    }
    append_str(body, ptr);

    memcpy(pckt->payload, payload, offset + strlen(body));


    unsigned char *begin = payload;
    unsigned char *end = payload + offset + strlen(body);

    pckt->checksum = crc32(begin, end);
    append_str("BE", pckt->start_header);
}

int rcon_send(int sckfd, char *buffer, int buffer_size, bool battleye) {
    int ret;
    if (battleye) {
        ret = sendto(sckfd, buffer, buffer_size, 0, (struct sockaddr *) &si_other, sockaddr_len);
    } else {
        ret = send(sckfd, buffer, buffer_size, 0);
    }
    return (ret);
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

int yarcon_server_connect(char *host,
                          char *port,
                          RconProtocolType type)
{
    int sckfd;
    sockaddr_len = sizeof(si_other);
    struct hostent *hostname = gethostbyname(host);
    si_other.sin_port = htons(atoi(port));
    si_other.sin_family = AF_INET;

    if( hostname != NULL) {
        memcpy(&si_other.sin_addr, hostname->h_addr_list[0], hostname->h_length);
    } else {
        si_other.sin_addr.s_addr = inet_addr(host);
    }

    // SOURCE
    if (type == RCON_SOURCE_PROTOCOL) {
        sckfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sckfd < 0) {
            perror("Failed to create TCP socket");
            exit(1);
        }
        int err = connect(sckfd, (struct sockaddr *) &si_other, sockaddr_len);
        if (err < 0) {
                perror("Cannot connect to server");
                exit(1);
        }
    } // BE
    else if (type == RCON_BATTLEYE_PROTOCOL) {
        if ((sckfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
            perror("Failed to create UDP socket");
            exit(1);
        }
    }

    return (sckfd);
}

// int yarcon_parse_input_file(GameServer *gameserver, char *input)
// {
//     FILE *fp = fopen(input, "rb");
//     if (NULL == fp) {
//         fprintf(stderr, "[!] Cannot open file %s\n", input);
//         exit(1);
//     }

//     char **lines = (char **) malloc(sizeof(char) * MAX_LINES_SIZE);
//     char *entry = malloc(sizeof(char) * MAX_LINE_SIZE);
//     memset(entry, 0, MAX_LINE_SIZE);
//     char *s = malloc(sizeof(char) * MAX_LINE_SIZE);
//     size_t size_lines_len = 0;
//     while (fgets(s, MAX_LINE_SIZE, fp)) {

//         // Clean one or more spaces
//         char *d = s;
//         char *ptr = entry;
//         while (*d != '\0') {
//             if (*d == ' ') {
//                 ++d;
//             } else {
//                 *entry++ = *d++;
//             }
//         }

//         entry = ptr;

//         lines[size_lines_len] = (char *) malloc(sizeof(char) * strlen(entry) - 1);
//         memcpy(lines[size_lines_len], entry, strlen(entry) - 1);
//         memset(entry, 0, MAX_LINE_SIZE);
//         size_lines_len++;
//     }

//     // Parser input data
//     for (size_t i = 0; i < size_lines_len; ++i) {
//         char *ptr_start = lines[i];
//         char *ptr_end = strchr(lines[i], ':');
//         size_t len = ptr_end - ptr_start;
//         char *field = malloc(sizeof(char) * len);
//         memset(field, 0, len);
//         memcpy(field, lines[i], len);

//         char *value = ptr_end + 1;
//         if (!strcmp("game", field)) {
//             memcpy(gameserver->game, value, strlen(value));
//         } else if (!strcmp("host", field)) {
//             memcpy(gameserver->host, value, strlen(value));
//         } else if (!strcmp("port", field)) {
//             memcpy(gameserver->port, value, strlen(value));
//         } else if (!strcmp("password", field)) {
//             memcpy(gameserver->password, value, strlen(value));
//         }
//     }

//     fclose(fp);
//     return (0);
// }

#endif // YARCON_H