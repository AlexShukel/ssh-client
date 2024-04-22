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

#define PORT 22

byte packet_buffer[MAX_PACKET_SIZE] = { 0 };

void init_connection(int *s_socket, struct sockaddr_in *server_addr) {
    if ((*s_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "ERROR: cannot create socket.\n");
        exit(1);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    (*server_addr).sin_family = AF_INET;
    (*server_addr).sin_port = htons(PORT);

    if (inet_aton("172.23.25.64", &server_addr->sin_addr) <= 0) {
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
    printf("Protocol version: %s", protocol_version);

    if (!starts_with(protocol_version, "SSH-2.0", 7)) {
        close(s_socket);
        fprintf(stderr, "ERROR: protocol_version is not valid\n");
        exit(1);
    }
}

void algorithm_negotiation(int s_socket) {
    KEXINIT kexinit_client;
    size_t kexinit_size = fill_kexinit(&kexinit_client);

    Packet kexinit_packet_client;
    size_t packet_size = fill_packet(&kexinit_packet_client, &kexinit_client, kexinit_size, NULL);

    size_t size = send(s_socket, &kexinit_packet_client, packet_size, 0);

    if (size == -1) {
        close(s_socket);
        fprintf(stderr, "ERROR: failed to send KEXINIT packet\n");
        exit(1);
    }

    Packet server_packet;
    size = recv(s_socket, packet_buffer, MAX_PACKET_SIZE, 0);

    if (size == -1) {
        close(s_socket);
        fprintf(stderr, "ERROR: failed to receive a kexinit packet\n");
        exit(1);
    }

    parse_packet(packet_buffer, &server_packet);

    KEXINIT kexinit_server;
    parse_kexinit(server_packet.payload, &kexinit_server);

//    if (size == -1) {
//        close(s_socket);
//        fprintf(stderr, "ERROR: failed to receive a kexinit_packet_server\n");
//        exit(1);
//    }
//
//    printf("Packet length: %d\nReal packet length: %d\n", kexinit_packet_server.packet_length, size);
}

int main() {
    int s_socket;
    struct sockaddr_in server_addr;

    init_connection(&s_socket, &server_addr);

    exchange_protocol_version(s_socket);
    algorithm_negotiation(s_socket);
    close(s_socket);
    return 0;
//
//    // Example: parsing packet_length field (assuming little-endian byte order)
//    kexinit_packet_server.packet_length = *((uint32_t *) &kexinit_packet_server);
//
//    // Example: parsing padding_length field
//    kexinit_packet_server.padding_length = *((byte *) &kexinit_packet_server + sizeof(uint32_t));
//
//    // Example: parsing payload field (assuming payload is contiguous after padding_length)
//    kexinit_packet_server.payload = (byte *) &kexinit_packet_server + sizeof(uint32_t) + sizeof(byte);
//
//    // Example: parsing random_padding field (assuming random_padding is contiguous after payload)
//    kexinit_packet_server.random_padding = kexinit_packet_server.payload + kexinit_packet_server.padding_length;
//
//    // Example: parsing mac field (assuming mac is contiguous after random_padding)
//    kexinit_packet_server.mac = kexinit_packet_server.random_padding + kexinit_packet_server.padding_length;
//
////    KEXINIT *kexinit_server = (KEXINIT *) kexinit_packet_server.payload;
//    KEXINIT kexinit_server;
//    memcpy(&kexinit_server, kexinit_packet_server.payload, sizeof(KEXINIT));
//
//    // Allocate memory for variable-length fields and copy data
//    kexinit_server.kex_algorithms = (char *) malloc(strlen((char *) kexinit_packet_server.payload + 17) + 1);
//    strcpy(kexinit_server.kex_algorithms, (char *) kexinit_packet_server.payload + 17);
//
//    // Print filled KEXINIT structure
//    printf("SSH_MSG_KEXINIT: %d\n", kexinit_server.SSH_MSG_KEXINIT);
//    printf("Cookie: ");
//    for (int i = 0; i < sizeof(kexinit_server.cookie); i++) {
//        printf("%02x", kexinit_server.cookie[i]);
//    }
//
//    printf("\n");
//    printf("Kex Algorithms: %s\n", kexinit_server.kex_algorithms);
//    printf("Server Host Key Algorithms: %s\n", kexinit_server.server_host_key_algorithms);
//    printf("Encryption Algorithms (Client to Server): %s\n", kexinit_server.encryption_algorithms_client_to_server);
//    printf("Encryption Algorithms (Server to Client): %s\n", kexinit_server.encryption_algorithms_server_to_client);
//    printf("MAC Algorithms (Client to Server): %s\n", kexinit_server.mac_algorithms_client_to_server);
//    printf("MAC Algorithms (Server to Client): %s\n", kexinit_server.mac_algorithms_server_to_client);
//    printf("Compression Algorithms (Client to Server): %s\n", kexinit_server.compression_algorithms_client_to_server);
//    printf("Compression Algorithms (Server to Client): %s\n", kexinit_server.compression_algorithms_server_to_client);
//    printf("Languages (Client to Server): %s\n", kexinit_server.languages_client_to_server);
//    printf("Languages (Server to Client): %s\n", kexinit_server.languages_server_to_client);
//    printf("First KEX Packet Follows: %d\n", kexinit_server.first_kex_packet_follows);
//    printf("Reserved: %u\n", kexinit_server.reserved);
//
//    close(s_socket);
//    return 0;
}
