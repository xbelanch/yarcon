// Storage Size of addrinfo isn't known: https://stackoverflow.com/questions/37541985/storage-size-of-addrinfo-isnt-known
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>     // read, write, close
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr
#include <sys/socket.h> // socket, connect
#include <netdb.h>      // struct hostent, gethostbyname
#include <arpa/inet.h>  // get IP addresses from sockaddr
#include "yarcon.h"
#include "color_utils.h"
#include "pzserver.h"

static char *host = NULL;
static char *port = NULL;
static char *password = NULL;
static char *command = NULL;
static char *config = NULL;
static int debug = false;
static int battleye = false;
// static char *server = NULL;
// static bool nowait = false;

static char *strremove(char *s, char chr) {
    char *e = malloc(sizeof(char) * 1024);
    memset(e, 0, 1024);

    char *d = s;
    char *ptr = e;
    while (*d != '\0') {
        if (*d == chr) {
            ++d;
        } else {
            *e++ = *d++;
        }
    }
    e = ptr;
    return (e);
}

static void print_usage()
{
    puts("");
    puts("YARCON " VERSION " - https://github.com/xbelanch/rcon");
    puts("Send rcon commands to game servers with rcon support.");
    puts("Usage: yarcon [OPTIONS] [COMMANDS]");
    puts("Options:");
    puts("-H\t\tHost address (example: 0.0.0.0)");
    puts("-P\t\tPort");
    puts("-p\t\tpassword");
    puts("-h\t\tPrint usage");
    puts("-v\t\tVersion");
    puts("-c\t\tCommand");
    puts("-f\t\tOpen config file");
    puts("Example:\n\tyarcon -H my.game.server -P port.server -p password -c \"status\"");
}

static void cleanup(void)
{
    // free(host);
    // free(port);
    // free(password);
    // free(command);
    // free(config);
}

void parse_input_file(char *filename)
{
    // Read and parse input file
    FILE *fp = fopen(filename, "rb");
    if (NULL == fp) {
        fprintf(stderr, "[!] Cannot open file %s\n", filename);
        exit(1);
    }

    char *s = malloc(sizeof(char) * 1024);

    while (fgets(s, MAX_LINE_SIZE, fp)) {

        char *entry = strremove(s, ' ');
        if (strncmp("host", entry, strlen("host")) == 0) {
            char *value = strchr(entry, ':') + 1;
            host = malloc(sizeof(char) * strlen(value) - 1); // remove \n
            strcpy(host, value);
        } else if (strncmp("port", entry, strlen("port")) == 0) {
            char *value = strchr(entry, ':') + 1;
            port = malloc(sizeof(char) * strlen(value) - 1); // remove \n
            strcpy(port, value);
        }
    }
    fclose(fp);
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
            free(config);
            len = strlen(optarg);
            config = calloc(1, len);
            memcpy(config, optarg, len);
            break;
        case 'd': debug = true; break;
        case 'b': battleye = true; break;
        case 'H':
            free(host);
            len = strlen(optarg);
            host = calloc(1, len);
            memcpy(host, optarg, len);
            break;
        case 'm': battleye = true; break;
        case 'p':
            free(port);
            len = strlen(optarg);
            port = calloc(1, len);
            memcpy(port, optarg, len);
            break;
        case 'P':
            free(password);
            len = strlen(optarg);
            password = calloc(1, len);
            memcpy(password, optarg, len);
            break;
        case 'c':
            free(command);
            len = strlen(optarg);
            command = calloc(1, len);
            memcpy(command, optarg, len);
            break;

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


    if (debug)
        fprintf(stdout, BGREEN "[i] " RESET "host: " BYELLOW "%s " RESET "port: " BYELLOW "%s " RESET "command: " BYELLOW "%s\n" RESET , host, port, command);

    // Source Rcon
    if (!battleye)
    {
        Pckt_Src_Struct pckt = { 0 };
        char buffer[MAX_BUFFER_SIZE];

        // Connect with server
        int sckfd = yarcon_server_connect(host, port, RCON_SOURCE_PROTOCOL);

        // Auth phase
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_source_packet(&pckt, SERVERDATA_AUTH, password);
        yarcon_serialize_data(&pckt, buffer);
        int buffer_size = 4 + 4 + 4 + strlen(password) + 2;
        // int ret = rcon_send(sckfd, buffer, buffer_size, battleye);
        // if (ret < 0) {
        //     perror("[!] \033[01;31mError\033[0m: failed to send packet");
        //     exit(1);
        // }

        int ret = send(sckfd, buffer, buffer_size, 0);
        if (ret < 0)
            perror("[!] \033[01;31mError\033[0m: failed to send packet");

        ret = recv(sckfd, buffer, buffer_size, 0);

        // Send command
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_source_packet(&pckt, SERVERDATA_EXECCOMMAND, command);
        yarcon_serialize_data(&pckt, buffer);
        buffer_size = 4 + 4 + 4 + strlen(command) + 2;
        ret = send(sckfd, buffer, buffer_size, 0);
        if (ret < 0)
            perror("[!] \033[01;31mError\033[0m: failed to send packet");

        ret = recv(sckfd, buffer, MAX_BUFFER_SIZE, 0);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        ret = recv(sckfd, buffer, MAX_BUFFER_SIZE, 0);
        Pckt_Src_Struct *res = (Pckt_Src_Struct *)buffer;
        fprintf(stdout, BGREEN "[i] " RESET "Response from server:\n" BPURPLE "%s" RESET, res->body);

        // TODO: Introducing game server functions
        fprintf(stdout, BRED "%d\n" RESET, pzserver_get_num_players(res->body));

        close(sckfd);
        sckfd = -1;
    } else
    // BE Rcon
    {
        Pckt_BE_Struct be_pckt = { 0 };
        char buffer[MAX_BUFFER_SIZE];

        int sckfd = yarcon_server_connect(host, port, RCON_BATTLEYE_PROTOCOL);

        // Auth phase
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_be_packet(&be_pckt, BE_PACKET_LOGIN, password);
        yarcon_serialize_be_data(&be_pckt, buffer);
        int buffer_size = 2 + sizeof(uint32_t) + 2 + strlen(password);
        rcon_send(sckfd, buffer, buffer_size, battleye);
        // sendto(sckfd, buffer, 2 + sizeof(uint32_t) + 2 + strlen(password), 0, (struct sockaddr *) &si_other, sockaddr_len);
        recvfrom(sckfd, buffer, 2048, 0, (struct sockaddr *) &si_other, &sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        recvfrom(sckfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &si_other, &sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);

        // Send command to game server
        yarcon_populate_be_packet(&be_pckt, BE_PACKET_COMMAND, command);
        yarcon_serialize_be_data(&be_pckt, buffer);

        sendto(sckfd, buffer, 2 + sizeof(uint32_t) + 3 + strlen(command), 0, (struct sockaddr *) &si_other, sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        recvfrom(sckfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &si_other, &sockaddr_len);
        Pckt_BE_Struct *res = (Pckt_BE_Struct *)buffer;
        printf("msg: %s\n", res->payload + 1);

        close(sckfd);
        sckfd = -1;
    }

    atexit(cleanup);

    return (0);
}