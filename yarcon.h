#ifndef YARCON_H
#define YARCON_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "color_utils.h"

#define PROGRAM_NAME "yarcon"
#define VERSION "0.1.0"
#define MAX_BUFFER_SIZE 4096
#define MAX_LINE_SIZE 64
#define SOURCE_RCON_TRAILER_SIZE 2
#define SOURCE_RCON_HEADER_SIZE (sizeof(int32_t) * 3)
#define SOURCE_RCON_SIZE_FIELD_SIZE sizeof(int32_t)
#define SOURCE_RCON_MIN_PACKET_SIZE 10
#define BATTLEYE_HEADER_SIZE ((sizeof(unsigned char) * 2) + sizeof(uint32_t))
#define BATTLEYE_PAYLOAD_PREFIX_SIZE 2
#define BATTLEYE_COMMAND_SEQUENCE_SIZE 1

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

typedef enum rcon_read_status
{
    RCON_READ_OK = 0,
    RCON_READ_TIMEOUT = -1,
    RCON_READ_CLOSED = -2,
    RCON_READ_SOCKET_ERROR = -3,
    RCON_READ_MALFORMED = -4,
} RconReadStatus;

typedef struct rcon_source_read_result
{
    RconReadStatus status;
    size_t bytes_read;
    int32_t packet_size;
} RconSourceReadResult;

static void print_usage()
{
    puts("");
    puts(RED "yarcon " VERSION RESET " - " GREEN "https://github.com/xbelanch/yarcon" RESET);
    puts("Send RCON commands to game servers with Source or Battleye RCON support.");
    puts("");
    puts("Usage:");
    puts("  yarcon -H HOST -p PORT -P PASSWORD -c COMMAND [OPTIONS]");
    puts("");
    puts("Options:");
    puts("  -H, --host HOST       Host name or IP address (example: 127.0.0.1)");
    puts("  -p, --port PORT       RCON port (example: 16261)");
    puts("  -P, --password PASS   RCON password");
    puts("  -c, --command CMD     Command to execute");
    puts("  -b, --battleye        Use Battleye RCON instead of Source RCON");
    puts("  -f, --config FILE     Read host and port from a simple config file");
    puts("  -d, --debug           Print connection details and packet traces");
    puts("  -h, --help            Show this help");
    puts("");
    puts("Examples:");
    puts(BLUE "  Source RCON:   " YELLOW "yarcon -H 127.0.0.1 -p 27015 -P password -c status" RESET);
    puts(BLUE "  Battleye RCON: " YELLOW "yarcon -b -H 127.0.0.1 -p 2301 -P password -c players" RESET);
}

static void print_error(const char *message)
{
    fprintf(stderr, RED "[!] " RESET "%s\n", message);
}

static bool parse_tcp_port(const char *port, uint16_t *out)
{
    char *end = NULL;
    long parsed;

    if (port == NULL || *port == '\0') {
        return false;
    }

    errno = 0;
    parsed = strtol(port, &end, 10);
    if (errno != 0 || end == port || *end != '\0' || parsed < 1 || parsed > 65535) {
        return false;
    }

    *out = (uint16_t) parsed;
    return true;
}

// CRC32 implementation used by the documented Battleye RCON packet format.
static uint32_t crc32(unsigned char *begin, unsigned char *end) {
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

static int serialize_int32_t(int32_t val, char *buffer)
{
    // Source RCON fields are sent little-endian by the protocol.
    memcpy(buffer, &val, sizeof(int32_t));
    return (0);
}

static int deserialize_int32_t(const char *buffer, int32_t *val)
{
    if (buffer == NULL || val == NULL) {
        return (-1);
    }

    memcpy(val, buffer, sizeof(int32_t));
    return (0);
}

static int rcon_serialize_data(Pckt_Src_Struct *pckt, char *buffer, size_t buffer_size)
{
    if (pckt == NULL || buffer == NULL || pckt->len > buffer_size) {
        return (-1);
    }

    char *ptr = buffer;
    serialize_int32_t(pckt->size, ptr);
    ptr += sizeof(int32_t);
    serialize_int32_t(pckt->id, ptr);
    ptr += sizeof(int32_t);
    serialize_int32_t(pckt->type, ptr);
    ptr += sizeof(int32_t);
    memcpy(ptr, pckt->body, strlen(pckt->body));
    ptr += strlen(pckt->body);
    *ptr++ = '\0';
    *ptr = '\0';

    return (0);
}

static const char *rcon_read_status_name(RconReadStatus status)
{
    switch (status) {
    case RCON_READ_OK:
        return "ok";
    case RCON_READ_TIMEOUT:
        return "timeout";
    case RCON_READ_CLOSED:
        return "connection closed";
    case RCON_READ_SOCKET_ERROR:
        return "socket error";
    case RCON_READ_MALFORMED:
        return "malformed packet";
    default:
        return "unknown";
    }
}

static void rcon_debug_body_preview(const char *body, bool redact)
{
    size_t i;
    size_t len;
    size_t preview_len;

    if (redact) {
        fputs("<redacted>", stderr);
        return;
    }

    if (body == NULL) {
        fputs("<null>", stderr);
        return;
    }

    len = strlen(body);
    preview_len = len > 160 ? 160 : len;
    fputc('"', stderr);
    for (i = 0; i < preview_len; i++) {
        unsigned char ch = (unsigned char) body[i];
        if (ch == '\n') {
            fputs("\\n", stderr);
        } else if (ch == '\r') {
            fputs("\\r", stderr);
        } else if (ch == '\t') {
            fputs("\\t", stderr);
        } else if (ch < 32 || ch > 126) {
            fprintf(stderr, "\\x%02x", ch);
        } else {
            fputc(ch, stderr);
        }
    }
    if (preview_len < len) {
        fputs("...", stderr);
    }
    fputc('"', stderr);
}

static void rcon_debug_source_packet(const char *direction, const Pckt_Src_Struct *pckt, bool redact_body)
{
    size_t body_len = 0;

    if (pckt == NULL) {
        return;
    }

    body_len = strlen(pckt->body);
    fprintf(stderr,
            CYAN "[debug] " RESET "%s Source packet: size=%d id=%d type=%d total_len=%zu body_len=%zu body=",
            direction, pckt->size, pckt->id, pckt->type, pckt->len, body_len);
    rcon_debug_body_preview(pckt->body, redact_body);
    fputc('\n', stderr);
}

static RconReadStatus rcon_recv_exact(int sckfd, char *buffer, size_t len, size_t *bytes_read)
{
    size_t received = 0;

    while (received < len) {
        ssize_t ret = recv(sckfd, buffer + received, len - received, 0);
        if (ret == 0) {
            if (bytes_read != NULL) {
                *bytes_read = received;
            }
            return RCON_READ_CLOSED;
        }
        if (ret < 0) {
            if (bytes_read != NULL) {
                *bytes_read = received;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return RCON_READ_TIMEOUT;
            }
            return RCON_READ_SOCKET_ERROR;
        }
        received += (size_t) ret;
    }

    if (bytes_read != NULL) {
        *bytes_read = received;
    }
    return RCON_READ_OK;
}

static RconSourceReadResult rcon_read_source_packet(int sckfd, Pckt_Src_Struct *pckt)
{
    RconSourceReadResult result = { RCON_READ_OK, 0, 0 };
    char size_buffer[SOURCE_RCON_SIZE_FIELD_SIZE];
    char payload[MAX_BUFFER_SIZE];
    int32_t packet_size;
    int32_t packet_type;
    size_t body_len;
    size_t chunk_read = 0;

    if (pckt == NULL) {
        result.status = RCON_READ_MALFORMED;
        return result;
    }

    memset(pckt, 0, sizeof(*pckt));
    memset(payload, 0, sizeof(payload));

    result.status = rcon_recv_exact(sckfd, size_buffer, sizeof(size_buffer), &chunk_read);
    result.bytes_read += chunk_read;
    if (result.status != RCON_READ_OK || deserialize_int32_t(size_buffer, &packet_size) < 0) {
        return result;
    }

    result.packet_size = packet_size;
    if (packet_size < SOURCE_RCON_MIN_PACKET_SIZE || (size_t) packet_size > sizeof(payload)) {
        result.status = RCON_READ_MALFORMED;
        return result;
    }

    result.status = rcon_recv_exact(sckfd, payload, (size_t) packet_size, &chunk_read);
    result.bytes_read += chunk_read;
    if (result.status != RCON_READ_OK) {
        return result;
    }

    if (deserialize_int32_t(payload, &pckt->id) < 0 ||
        deserialize_int32_t(payload + sizeof(int32_t), &packet_type) < 0) {
        result.status = RCON_READ_MALFORMED;
        return result;
    }
    pckt->size = packet_size;
    pckt->type = (PacketSourceType) packet_type;
    pckt->len = SOURCE_RCON_SIZE_FIELD_SIZE + (size_t) packet_size;

    body_len = (size_t) packet_size - (sizeof(int32_t) * 2) - SOURCE_RCON_TRAILER_SIZE;
    if (body_len >= sizeof(pckt->body)) {
        result.status = RCON_READ_MALFORMED;
        return result;
    }

    memcpy(pckt->body, payload + (sizeof(int32_t) * 2), body_len);
    pckt->body[body_len] = '\0';
    return result;
}

static int rcon_populate_source_packet(Pckt_Src_Struct *pckt, PacketSourceType type, const char *body)
{
    size_t body_len;

    if (pckt == NULL || body == NULL) {
        return (-1);
    }

    body_len = strlen(body);
    if (body_len >= sizeof(pckt->body)) {
        return (-1);
    }

    pckt->size = (int32_t) ((sizeof(uint32_t) * 2) + body_len + SOURCE_RCON_TRAILER_SIZE);
    pckt->id = abs(rand());
    pckt->type = type;
    pckt->len = SOURCE_RCON_HEADER_SIZE + body_len + SOURCE_RCON_TRAILER_SIZE;
    memcpy(pckt->body, body, body_len + 1);
    return (0);
}

static int rcon_connect_source(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry = NULL;
    int err;
    int sckfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo(host, port, &hints, &results);
    if (err != 0) {
        fprintf(stderr, RED "[!] " RESET "Could not resolve host: %s\n", gai_strerror(err));
        exit(1);
    }

    for (entry = results; entry != NULL; entry = entry->ai_next) {
        sckfd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (sckfd < 0) {
            continue;
        }

        if (connect(sckfd, entry->ai_addr, entry->ai_addrlen) == 0) {
            break;
        }

        close(sckfd);
        sckfd = -1;
    }

    freeaddrinfo(results);

    if (sckfd < 0) {
        perror(RED "[!] " RESET "Error");
        exit(1);
    }

    return sckfd;
}

static int rcon_serialize_be_data(Pckt_BE_Struct *pckt, char *buffer, size_t buffer_size, size_t payload_size)
{
    size_t packet_size = BATTLEYE_HEADER_SIZE + payload_size;

    if (pckt == NULL || buffer == NULL || packet_size > buffer_size || payload_size > sizeof(pckt->payload)) {
        return (-1);
    }

    char *ptr = buffer;
    memcpy(ptr, pckt->start_header, sizeof(unsigned char) * 2);
    ptr += sizeof(unsigned char) * 2;
    memcpy(ptr, &pckt->checksum, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, pckt->payload, payload_size);
    return (0);
}

static int rcon_populate_be_packet(Pckt_BE_Struct *pckt, PacketBattleyeType type, const char *body, size_t *payload_size)
{
    // Battleye checksums cover only the payload after the "BE" packet header.
    unsigned char payload[MAX_BUFFER_SIZE];
    unsigned char *ptr = payload;
    size_t body_len;
    size_t prefix_len = BATTLEYE_PAYLOAD_PREFIX_SIZE;

    if (pckt == NULL || body == NULL || payload_size == NULL) {
        return (-1);
    }

    body_len = strlen(body);
    if (type == BE_PACKET_COMMAND) {
        prefix_len += BATTLEYE_COMMAND_SEQUENCE_SIZE;
    }

    if (prefix_len + body_len > sizeof(pckt->payload)) {
        return (-1);
    }

    memset(payload, 0, sizeof(payload));
    *ptr++ = 0xFF;
    *ptr++ = (unsigned char) type;
    if (type == BE_PACKET_COMMAND) {
        *ptr++ = 0x00;
    }
    memcpy(ptr, body, body_len);

    *payload_size = prefix_len + body_len;
    memcpy(pckt->payload, payload, *payload_size);

    unsigned char *begin = payload;
    unsigned char *end = payload + *payload_size;

    pckt->checksum = crc32(begin, end);
    pckt->start_header[0] = 'B';
    pckt->start_header[1] = 'E';
    return (0);
}

static int rcon_server_connect(const char *host,
                               const char *port,
                               RconProtocolType type)
{
    int sckfd = -1;
    uint16_t parsed_port = 0;

    if (!parse_tcp_port(port, &parsed_port)) {
        print_error("Invalid port. Use a number between 1 and 65535.");
        exit(1);
    }

    if (type == RCON_SOURCE_PROTOCOL) {
        return rcon_connect_source(host, port);
    } else if (type == RCON_BATTLEYE_PROTOCOL) {
        struct hostent *hostname = gethostbyname(host);

        sockaddr_len = sizeof(si_other);
        memset(&si_other, 0, sizeof(si_other));
        si_other.sin_port = htons(parsed_port);
        si_other.sin_family = AF_INET;

        if (hostname != NULL) {
            memcpy(&si_other.sin_addr, hostname->h_addr_list[0], hostname->h_length);
        } else {
            si_other.sin_addr.s_addr = inet_addr(host);
            if (si_other.sin_addr.s_addr == INADDR_NONE) {
                print_error("Could not resolve host.");
                exit(1);
            }
        }

        if ((sckfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
            perror(RED "[!] " RESET "Error");
            exit(1);
        }
    }

    return (sckfd);
}

static int rcon_send(int sckfd, const char *buffer, size_t buffer_size, bool battleye) {
    ssize_t ret;
    if (battleye) {
        ret = sendto(sckfd, buffer, buffer_size, 0, (struct sockaddr *) &si_other, sockaddr_len);
    } else {
        size_t sent = 0;
        while (sent < buffer_size) {
            ret = send(sckfd, buffer + sent, buffer_size - sent, 0);
            if (ret <= 0) {
                break;
            }
            sent += (size_t) ret;
        }
        ret = (sent == buffer_size) ? (ssize_t) sent : -1;
    }
    if (ret == -1) {
        perror(RED "[!] " RESET "Error");
        return (-1);
    } else {
        return (ret);
    }
}

#endif // YARCON_H
