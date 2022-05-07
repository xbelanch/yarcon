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

    char buffer[256];
    memset(buffer, '\0', 256);

    // 0. Display name and version
    puts(PROGRAM_NAME " " VERSION);

    // 1. Parse input data from file
    GameServer gameserver = { 0 };
    yarcon_parse_input_file(&gameserver, argv[1]);
    fprintf(stdout, BGREEN "[i] " RESET "Game server: " BYELLOW "%s\n" RESET, gameserver.game);

    // 2. Populate auth packet
    Pckt_Src_Struct pckt = { 0 };
    yarcon_populate_source_packet(&pckt, SERVERDATA_AUTH, gameserver.password);

    // 3. Serialize data
    yarcon_serialize_data(&pckt, buffer);

    // 4. Connect to remote host
    int sck = yarcon_connect_gamserver(gameserver.host, gameserver.port);

    // 5. Auth
    int ret = yarcon_send_packet(sck, buffer, pckt.len);

    char recv_buffer[MAX_BUFFER_SIZE];
    memset(recv_buffer, 0, MAX_BUFFER_SIZE);
    if (ret == 0)
    {
        ret = yarcon_receive_response(sck, recv_buffer, MAX_BUFFER_SIZE);
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

    // 6.3 Recieve
    memset(recv_buffer, 0, MAX_BUFFER_SIZE);
    if (ret == 0)
    {
        ret = yarcon_receive_response(sck, recv_buffer, MAX_BUFFER_SIZE);
        Pckt_Src_Struct *res = (Pckt_Src_Struct *)recv_buffer;
        // printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);

        // 6.4 Deserialize data from server if auth response is ok
        // TODO: handle multiple-packet responses
        if (res->id > 0) {
            memset(recv_buffer, 0, MAX_BUFFER_SIZE);
            ret = yarcon_receive_response(sck, recv_buffer, MAX_BUFFER_SIZE);
            res = (Pckt_Src_Struct *)recv_buffer;
            // printf("size: %u, id: %u, type: %u, body: %s\n", res->size, res->id, res->type, res->body);
            fprintf(stdout, BGREEN "[i] " RESET "Response from game server:\n" BPURPLE "%s" RESET, res->body);
            // TODO: Introducing game server functions
            fprintf(stdout, BRED "%d\n" RESET, pzserver_get_num_players(res->body));

        } else {
            memset(recv_buffer, 0, MAX_BUFFER_SIZE);
            ret = yarcon_receive_response(sck, recv_buffer, MAX_BUFFER_SIZE);
            res = (Pckt_Src_Struct *)recv_buffer;
            printf("res->id: %u Something went wrong. Maybe password is not set properly.\n", res->id);
        }
    }

    return (0);
}