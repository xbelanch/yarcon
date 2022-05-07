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
