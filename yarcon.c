// Storage Size of addrinfo isn't known: https://stackoverflow.com/questions/37541985/storage-size-of-addrinfo-isnt-known
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>     // read, write, close
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr
#include <sys/socket.h> // socket, connect
#include <netdb.h>      // struct hostent, gethostbyname
#include <arpa/inet.h>  // get IP addresses from sockaddr
#include "yarcon.h"
#include "color_utils.h"

static char *host = NULL;
static char *port = NULL;
static char *password = NULL;
static char *command = NULL;
static char *config = NULL;
static int debug = false;
static int battleye = false;
static bool host_owned = false;
static bool port_owned = false;
// static char *server = NULL;
// static bool nowait = false;

static void replace_string(char **target, bool *owned, const char *value)
{
    char *copy;

    if (value == NULL) {
        return;
    }

    copy = malloc(strlen(value) + 1);
    if (copy == NULL) {
        perror(RED "[!] " RESET "malloc");
        exit(1);
    }
    strcpy(copy, value);

    if (*owned) {
        free(*target);
    }

    *target = copy;
    *owned = true;
}

static char *trim_whitespace(char *value)
{
    char *end;

    while (isspace((unsigned char) *value)) {
        value++;
    }

    if (*value == '\0') {
        return value;
    }

    end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char) *end)) {
        *end = '\0';
        end--;
    }

    return value;
}

static void parse_input_file(const char *filename)
{
    // Config files accept "host: value" and "port: value" lines.
    FILE *fp = fopen(filename, "rb");
    char line[MAX_LINE_SIZE];

    if (NULL == fp) {
        fprintf(stderr, "[!] Cannot open file %s\n", filename);
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *entry = trim_whitespace(line);
        char *separator;
        char *key;
        char *value;

        if (*entry == '\0' || *entry == '#') {
            continue;
        }

        separator = strchr(entry, ':');
        if (separator == NULL) {
            continue;
        }

        *separator = '\0';
        key = trim_whitespace(entry);
        value = trim_whitespace(separator + 1);

        if (strcmp("host", key) == 0 && host == NULL) {
            replace_string(&host, &host_owned, value);
        } else if (strcmp("port", key) == 0 && port == NULL) {
            replace_string(&port, &port_owned, value);
        }
    }
    fclose(fp);
}

static void cleanup_args(void)
{
    if (host_owned) {
        free(host);
        host = NULL;
        host_owned = false;
    }
    if (port_owned) {
        free(port);
        port = NULL;
        port_owned = false;
    }
    free(config);
    config = NULL;
}

static void validate_args(void)
{
    uint16_t parsed_port;

    if (host == NULL || port == NULL || password == NULL || command == NULL) {
        print_error("Missing required arguments.");
        print_usage();
        cleanup_args();
        exit(1);
    }

    if (!parse_tcp_port(port, &parsed_port)) {
        print_error("Invalid port. Use a number between 1 and 65535.");
        cleanup_args();
        exit(1);
    }
}

static int parse_args(int ac, char *av[])
{
    static struct option opts[] = {
        { "config", required_argument, 0, 'f' },
        { "debug", no_argument, 0, 'd' },
        { "help", no_argument, 0, 'h' },
        { "host", required_argument, 0, 'H' },
        { "port", required_argument, 0, 'p' },
        { "battleye", no_argument, 0, 'b' },
        { "password", required_argument, 0, 'P' },
        { "command", required_argument, 0, 'c' },
        { NULL, 0, 0, 0 }
    };

    static char const *optstr = "f:dhH:p:bP:c:1";

    int c = 0;
    size_t len = 0;

    // No parameters passed
    if (ac == 1) {
        print_usage();
        exit(1);
    }

    while ((c = getopt_long(ac, av, optstr, opts, NULL)) != -1) {
        switch (c)
        {
        case 0:
            break;
        case 'f':
            len = strlen(optarg);
            config = calloc(1, len + 1);
            if (config == NULL) {
                perror(RED "[!] " RESET "calloc");
                exit(1);
            }
            memcpy(config, optarg, len + 1);
            break;
        case 'd': debug = true; break;
        case 'b': battleye = true; break;
        case 'H': host = optarg; break;
        case 'm': battleye = true; break;
        case 'p': port = optarg; break;
        case 'P': password = optarg; break;
        case 'c': command = optarg; break;

        case '1': /* backward compability */ break;
        case 'h': print_usage(); exit(0); break;
        default: print_usage(); exit(1); break;
        case '?': print_usage(); exit(1); break;
        }
    }

    return(0);
}

int main(int argc, char *argv[])
{
    // Use current time as seed for random generator
    srand(time(0));
    parse_args(argc, argv);
    atexit(cleanup_args);
    if (config != NULL) {
        parse_input_file(config);
    }
    validate_args();

    if (debug) {
        fprintf(stdout, BGREEN "[i] " RESET "host: " BYELLOW "%s " RESET "port: " BYELLOW "%s " RESET "command: " BYELLOW "%s " RESET "battleye: " BYELLOW, host, port, command);
        if (battleye) {
            puts("true" RESET);
        } else {
            puts("false" RESET);
        }
    }

    // Source Rcon
    if (!battleye)
    {
        Pckt_Src_Struct pckt = { 0 };
        Pckt_Src_Struct res = { 0 };
        RconSourceReadResult read_result = { 0 };
        char buffer[MAX_BUFFER_SIZE];
        int auth_id;

        // Connect with server
        if (debug) {
            fprintf(stderr, CYAN "[debug] " RESET "Opening Source RCON TCP connection to %s:%s\n", host, port);
        }
        int sckfd = rcon_server_connect(host, port, RCON_SOURCE_PROTOCOL);
        if (debug) {
            fprintf(stderr, CYAN "[debug] " RESET "TCP connection established\n");
        }

        // Fix issue on sometimes recv hangs executed from local server
        // works better using hostname instead of 0.0.0.0
        // from: https://stackoverflow.com/questions/2876024/linux-is-there-a-read-or-recv-from-socket-with-timeout
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sckfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        // Auth phase
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        if (rcon_populate_source_packet(&pckt, SERVERDATA_AUTH, password) < 0 ||
            rcon_serialize_data(&pckt, buffer, sizeof(buffer)) < 0) {
            print_error("Password is too long to fit in a Source RCON packet.");
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        size_t buffer_size = pckt.len;
        auth_id = pckt.id;
        if (debug) {
            rcon_debug_source_packet("send auth", &pckt, true);
        }
        int ret = rcon_send(sckfd, buffer, buffer_size, false);
        if (ret < 0) {
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        read_result = rcon_read_source_packet(sckfd, &res);
        if (debug) {
            fprintf(stderr, CYAN "[debug] " RESET "read auth response: status=%s bytes=%zu declared_size=%d\n",
                    rcon_read_status_name(read_result.status), read_result.bytes_read, read_result.packet_size);
            if (read_result.status == RCON_READ_OK) {
                rcon_debug_source_packet("recv auth response", &res, false);
            }
        }
        if (read_result.status != RCON_READ_OK) {
            fprintf(stderr, RED "[!] " RESET "Could not read Source RCON auth response: %s\n",
                    rcon_read_status_name(read_result.status));
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        if (res.type == SERVERDATA_RESPONSE_VALUE) {
            read_result = rcon_read_source_packet(sckfd, &res);
            if (debug) {
                fprintf(stderr, CYAN "[debug] " RESET "read auth confirmation: status=%s bytes=%zu declared_size=%d\n",
                        rcon_read_status_name(read_result.status), read_result.bytes_read, read_result.packet_size);
                if (read_result.status == RCON_READ_OK) {
                    rcon_debug_source_packet("recv auth confirmation", &res, false);
                }
            }
            if (read_result.status != RCON_READ_OK) {
                fprintf(stderr, RED "[!] " RESET "Could not read Source RCON auth confirmation: %s\n",
                        rcon_read_status_name(read_result.status));
                close(sckfd);
                cleanup_args();
                exit(1);
            }
        }

        if (res.id == -1 || res.id != auth_id) {
            print_error("Authentication failed. Check the RCON password.");
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        // Send command
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        pckt = (Pckt_Src_Struct) { 0 };

        if (rcon_populate_source_packet(&pckt, SERVERDATA_EXECCOMMAND, command) < 0 ||
            rcon_serialize_data(&pckt, buffer, sizeof(buffer)) < 0) {
            print_error("Command is too long to fit in a Source RCON packet.");
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        buffer_size = pckt.len;

        if (debug) {
            rcon_debug_source_packet("send command", &pckt, false);
        }
        ret = rcon_send(sckfd, buffer, buffer_size, false);
        if (ret < 0) {
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        read_result = rcon_read_source_packet(sckfd, &res);
        if (debug) {
            fprintf(stderr, CYAN "[debug] " RESET "read command response: status=%s bytes=%zu declared_size=%d\n",
                    rcon_read_status_name(read_result.status), read_result.bytes_read, read_result.packet_size);
            if (read_result.status == RCON_READ_OK) {
                rcon_debug_source_packet("recv command response", &res, false);
            }
        }
        if (read_result.status != RCON_READ_OK) {
            fprintf(stderr, RED "[!] " RESET "Could not read Source RCON command response: %s\n",
                    rcon_read_status_name(read_result.status));
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        fprintf(stdout, BGREEN "[i] " RESET "Response from server:\n" BPURPLE "%s\n" RESET, res.body);

        close(sckfd);
        sckfd = -1;
    } else
    // BE Rcon
    {
        Pckt_BE_Struct be_pckt = { 0 };
        char buffer[MAX_BUFFER_SIZE];

        int sckfd = rcon_server_connect(host, port, RCON_BATTLEYE_PROTOCOL);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sckfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        // Auth phase
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        size_t payload_size = 0;
        if (rcon_populate_be_packet(&be_pckt, BE_PACKET_LOGIN, password, &payload_size) < 0 ||
            rcon_serialize_be_data(&be_pckt, buffer, sizeof(buffer), payload_size) < 0) {
            print_error("Password is too long to fit in a Battleye RCON packet.");
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        size_t buffer_size = BATTLEYE_HEADER_SIZE + payload_size;

        if (rcon_send(sckfd, buffer, buffer_size, battleye) < 0) {
            close(sckfd);
            cleanup_args();
            exit(1);
        }
        if (recvfrom(sckfd, buffer, 2048, 0, (struct sockaddr *) &si_other, &sockaddr_len) < 0) {
            perror(RED "[!] " RESET "Error");
            close(sckfd);
            cleanup_args();
            exit(1);
        }
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        if (recvfrom(sckfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &si_other, &sockaddr_len) < 0) {
            perror(RED "[!] " RESET "Error");
            close(sckfd);
            cleanup_args();
            exit(1);
        }
        memset(buffer, '\0', MAX_BUFFER_SIZE);

        // Send command to game server
        if (rcon_populate_be_packet(&be_pckt, BE_PACKET_COMMAND, command, &payload_size) < 0 ||
            rcon_serialize_be_data(&be_pckt, buffer, sizeof(buffer), payload_size) < 0) {
            print_error("Command is too long to fit in a Battleye RCON packet.");
            close(sckfd);
            cleanup_args();
            exit(1);
        }

        if (rcon_send(sckfd, buffer, BATTLEYE_HEADER_SIZE + payload_size, battleye) < 0) {
            close(sckfd);
            cleanup_args();
            exit(1);
        }
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        if (recvfrom(sckfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &si_other, &sockaddr_len) < 0) {
            perror(RED "[!] " RESET "Error");
            close(sckfd);
            cleanup_args();
            exit(1);
        }
        Pckt_BE_Struct *res = (Pckt_BE_Struct *)buffer;
        // printf("msg: %s\n", res->payload + 1);
        fprintf(stdout, BGREEN "[i] " RESET "Response from server:\n" BPURPLE "%s\n" RESET, res->payload + 1);

        close(sckfd);
        sckfd = -1;
    }

    cleanup_args();
    return (0);
}
