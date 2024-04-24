#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "packet.h"
#include "kexinit.h"
#include "utils.h"
#include "dekexinit.h"

#define PORT 22

byte packet_buffer[MAX_PACKET_SIZE] = { 0 };

void init_connection(int *s_socket, struct sockaddr_in *server_addr, char *ip) {
    if ((*s_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "ERROR: cannot create socket.\n");
        exit(1);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    (*server_addr).sin_family = AF_INET;
    (*server_addr).sin_port = htons(PORT);

    if (inet_aton(ip, &server_addr->sin_addr) <= 0) {
        fprintf(stderr, "ERROR: Invalid remote IP address.\n");
        exit(1);
    }

    if (connect(*s_socket, (const struct sockaddr *) server_addr, sizeof(*server_addr)) < 0) {
        fprintf(stderr, "ERROR: error in connect().\n");
        exit(1);
    }
}

void exchange_protocol_version(int s_socket) {
    char *handshake_message = "SSH-2.0-1.0\r\n";
    ssize_t size;
    size = send(s_socket, handshake_message, 13, 0);

    if (size == -1) {
        close(s_socket);
        fprintf(stderr, "ERROR: failed to send a message\n");
        exit(1);
    }

    char protocol_version[256];
    size = recv(s_socket, protocol_version, 256, 0);

    if (size == -1) {
        close(s_socket);
        fprintf(stderr, "ERROR: failed to receive a protocol_version\n");
        exit(1);
    }

    protocol_version[size] = '\0';
    printf("Protocol version: %s\n", protocol_version);

    if (!starts_with(protocol_version, "SSH-2.0", 7)) {
        close(s_socket);
        fprintf(stderr, "ERROR: protocol_version is not valid\n");
        exit(1);
    }
}

void algorithm_negotiation(int s_socket) {
    KEXINIT kexinit_client;
    size_t kexinit_size = fill_kexinit(&kexinit_client);
    // FIXME: serialize KEXINIT properly
    send_data_in_packet(s_socket, (byte *) &kexinit_client, kexinit_size);

    Packet server_packet;
    size_t size = recv(s_socket, packet_buffer, MAX_PACKET_SIZE, 0);

    if (size == -1) {
        close(s_socket);
        fprintf(stderr, "ERROR: failed to receive a KEXINIT packet\n");
        exit(1);
    }

    deserialize_packet(packet_buffer, &server_packet);

    KEXINIT kexinit_server;
    deserialize_KEXINIT(server_packet.payload, &kexinit_server);
}

void key_exchange(int s_socket) {
    DEKEXINIT dekexinit;
    fill_dekexinit(&dekexinit);
    send_data_in_packet(s_socket, &dekexinit, sizeof(DEKEXINIT));

    Packet dekex_reply_packet;
    ssize_t size = recv(s_socket, packet_buffer, MAX_PACKET_SIZE, 0);
    deserialize_packet(packet_buffer, &dekex_reply_packet);
    printf("Size: %d\n", size);
    printf("Packet length: %d\n", dekex_reply_packet.packet_length);
}

int main(int argc, char **argv) {
    char *ip = argv[1];

    int s_socket;
    struct sockaddr_in server_addr;

    init_connection(&s_socket, &server_addr, ip);
    exchange_protocol_version(s_socket);

    algorithm_negotiation(s_socket);
//    key_exchange(s_socket);

    close(s_socket);
    return 0;
}
