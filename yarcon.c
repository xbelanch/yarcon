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
#include "yarcon.h"
#include "color_utils.h"
#include "pzserver.h"

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv[0];

    // Parse input data from file
    GameServer gameserver = { 0 };

    // TODO: Parse input arguments
    yarcon_parse_input_file(&gameserver, argv[1]);

    // BE Rcon
    {
        Pckt_BE_Struct be_pckt = { 0 };
        char buffer[MAX_BUFFER_SIZE];

        int sockfd;
        struct sockaddr_in si_other;
        unsigned int sockaddr_len = sizeof(si_other);
        {
            if ( (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
                perror("socket failed");
                return 1;
            }

            struct hostent *hostname = gethostbyname(gameserver.host);
            if(hostname) {
                memcpy(&si_other.sin_addr, hostname->h_addr_list[0], hostname->h_length);
            } else {
                si_other.sin_addr.s_addr = inet_addr(gameserver.host);
            }
            si_other.sin_family = AF_INET;
            si_other.sin_port = htons(atoi(gameserver.port));
        }

        // Send auth
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_be_packet(&be_pckt, BE_PACKET_LOGIN, gameserver.password);
        yarcon_serialize_be_data(&be_pckt, buffer);

        sendto(sockfd, buffer, 2 + sizeof(uint32_t) + 2 + strlen(gameserver.password), 0, (struct sockaddr *) &si_other, sockaddr_len);
        recvfrom(sockfd, buffer, 2048, 0, (struct sockaddr *) &si_other, &sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &si_other, &sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);

        // Send command
        yarcon_populate_be_packet(&be_pckt, BE_PACKET_COMMAND, "players");
        yarcon_serialize_be_data(&be_pckt, buffer);

        sendto(sockfd, buffer, 2 + sizeof(uint32_t) + 3 + strlen("players"), 0, (struct sockaddr *) &si_other, sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &si_other, &sockaddr_len);
        Pckt_BE_Struct *res = (Pckt_BE_Struct *)buffer;
        printf("msg: %s\n", res->payload + 1);

    }

    return (0);
}

int main2(int argc, char *argv[])
{
    (void) argc;
    (void) argv[0];

    char buffer[MAX_BUFFER_SIZE];
    // char recv_buffer[MAX_BUFFER_SIZE];

    memset(buffer, '\0', MAX_BUFFER_SIZE);
    // memset(recv_buffer, '\0', MAX_BUFFER_SIZE);

    // Display name and version
    puts(PROGRAM_NAME " " VERSION);

    // Parse input data from file
    GameServer gameserver = { 0 };

    // TODO: Parse input arguments
    yarcon_parse_input_file(&gameserver, argv[1]);

    // IF LOG
    fprintf(stdout, BGREEN "[i] " RESET "Game server: " BYELLOW "%s\n" RESET, gameserver.game);

    // Populate auth packet
    Pckt_Src_Struct pckt = { 0 };
    yarcon_populate_source_packet(&pckt, SERVERDATA_AUTH, gameserver.password);

    // Serialize data
    yarcon_serialize_data(&pckt, buffer);

    // Connect to remote host
    // TODO: Rewrite this dumb piece of code
    int sck;
    if (!strcmp(gameserver.game, "pzserver")) {
        // All that gameservers using source rcon protocol
        sck = yarcon_connect_gameserver(gameserver.host, gameserver.port, RCON_SOURCE_PROTOCOL);
    } else {
        // Arma3 and other game servers using battleye rcon protocol
        sck = yarcon_connect_gameserver(gameserver.host, gameserver.port, RCON_BATTLEYE_PROTOCOL);
    }

    // Send auth packet
    int ret = yarcon_send_packet(sck, buffer, pckt.len);

    if (ret == 0)
    {
        ret = yarcon_receive_response(sck, buffer, MAX_BUFFER_SIZE);
    }

    // 6. Send and execute command
    // Send message to Project Zomboid Server
    char *cmd = "players";
    // body = "servermsg \"Server will restart in 5 minutes\"";
    // Send message to Rust Legacy Server
    // body = "notice.popupall \"Server will restart in 5 minutes\"";
    // body = "find *";
    yarcon_populate_source_packet(&pckt, SERVERDATA_EXECCOMMAND, cmd);
    // 6.1. Serialize data
    yarcon_serialize_data(&pckt, buffer);
    // 6.2 Send
    ret = yarcon_send_packet(sck, buffer, pckt.len);
    if (ret == -1) {
        perror(BRED "[!] " RESET "Error: failed to send packet\n");
        return (-1);
    }

    // Recieve
    memset(buffer, 0, MAX_BUFFER_SIZE);
    if (ret == 0)
    {
        ret = yarcon_receive_response(sck, buffer, MAX_BUFFER_SIZE);
        Pckt_Src_Struct *res = (Pckt_Src_Struct *)buffer;
        // printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);

        // 6.4 Deserialize data from server if auth response is ok
        // TODO: handle multiple-packet responses
        if (res->id > 0) {
            memset(buffer, 0, MAX_BUFFER_SIZE);
            ret = yarcon_receive_response(sck, buffer, MAX_BUFFER_SIZE);
            res = (Pckt_Src_Struct *)buffer;
            // printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);
            fprintf(stdout, BGREEN "[i] " RESET "Response from game server:\n" BPURPLE "%s" RESET, res->body);
            // TODO: Introducing game server functions
            fprintf(stdout, BRED "%d\n" RESET, pzserver_get_num_players(res->body));

        } else {
            memset(buffer, 0, MAX_BUFFER_SIZE);
            ret = yarcon_receive_response(sck, buffer, MAX_BUFFER_SIZE);
            res = (Pckt_Src_Struct *)buffer;
            printf("res->id: %u Something went wrong. Maybe password is not set properly.\n", res->id);
        }
    }

    return (0);
}