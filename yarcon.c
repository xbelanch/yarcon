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

    // Display name and version
    puts(PROGRAM_NAME " " VERSION);

    // Parse input data from file
    GameServer gameserver = { 0 };

    // TODO: Parse input arguments
    yarcon_parse_input_file(&gameserver, argv[1]);

    // IF LOG
    fprintf(stdout, BGREEN "[i] " RESET "Game server: " BYELLOW "%s\n" RESET, gameserver.game);

#ifdef SOURCE
    // Source Rcon
    {
        Pckt_Src_Struct pckt = { 0 };
        char buffer[MAX_BUFFER_SIZE];

        // Connect with server
        int sckfd = yarcon_server_connect(&gameserver, RCON_SOURCE_PROTOCOL);

        // Auth phase
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_source_packet(&pckt, SERVERDATA_AUTH, gameserver.password);
        yarcon_serialize_data(&pckt, buffer);
        int buffer_size = 4 + 4 + 4 + strlen(gameserver.password) + 2;
        int ret = send(sckfd, buffer, buffer_size, 0);
        if (ret < 0)
            perror("[!] \033[01;31mError\033[0m: failed to send packet");

        ret = recv(sckfd, buffer, buffer_size, 0);

        // Send command
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_source_packet(&pckt, SERVERDATA_EXECCOMMAND, "players");
        yarcon_serialize_data(&pckt, buffer);
        buffer_size = 4 + 4 + 4 + strlen("players") + 2;
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
    }
#endif

#ifdef BATTLEYE
    // BE Rcon
    {
        Pckt_BE_Struct be_pckt = { 0 };
        char buffer[MAX_BUFFER_SIZE];

        int sckfd = yarcon_server_connect(&gameserver, RCON_BATTLEYE_PROTOCOL);

        // Auth phase
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        yarcon_populate_be_packet(&be_pckt, BE_PACKET_LOGIN, gameserver.password);
        yarcon_serialize_be_data(&be_pckt, buffer);

        sendto(sckfd, buffer, 2 + sizeof(uint32_t) + 2 + strlen(gameserver.password), 0, (struct sockaddr *) &gameserver.si_other, gameserver.sockaddr_len);
        recvfrom(sckfd, buffer, 2048, 0, (struct sockaddr *) &gameserver.si_other, &gameserver.sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        recvfrom(sckfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &gameserver.si_other, &gameserver.sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);

        // Send command to game server
        yarcon_populate_be_packet(&be_pckt, BE_PACKET_COMMAND, "players");
        yarcon_serialize_be_data(&be_pckt, buffer);

        sendto(sckfd, buffer, 2 + sizeof(uint32_t) + 3 + strlen("players"), 0, (struct sockaddr *) &gameserver.si_other, gameserver.sockaddr_len);
        memset(buffer, '\0', MAX_BUFFER_SIZE);
        recvfrom(sckfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &gameserver.si_other, &gameserver.sockaddr_len);
        Pckt_BE_Struct *res = (Pckt_BE_Struct *)buffer;
        printf("msg: %s\n", res->payload + 1);

        close(sckfd);
        sckfd = -1;
    }
#endif

    return (0);
}