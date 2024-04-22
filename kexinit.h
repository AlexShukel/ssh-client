//
// Created by aleksandras on 4/22/2024.
//

#ifndef SSH_IMPLEMENTATION_KEXINIT_H
#define SSH_IMPLEMENTATION_KEXINIT_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "shared.h"

typedef struct {
    byte SSH_MSG_KEXINIT;
    byte cookie[16];
    uint32_t kex_algorithms_length;
    char *kex_algorithms;
    uint32_t server_host_key_algorithms_length;
    char *server_host_key_algorithms;
    uint32_t encryption_algorithms_client_to_server_length;
    char *encryption_algorithms_client_to_server;
    uint32_t encryption_algorithms_server_to_client_length;
    char *encryption_algorithms_server_to_client;
    uint32_t mac_algorithms_client_to_server_length;
    char *mac_algorithms_client_to_server;
    uint32_t mac_algorithms_server_to_client_length;
    char *mac_algorithms_server_to_client;
    uint32_t compression_algorithms_client_to_server_length;
    char *compression_algorithms_client_to_server;
    uint32_t compression_algorithms_server_to_client_length;
    char *compression_algorithms_server_to_client;
    uint32_t languages_client_to_server_length;
    char *languages_client_to_server;
    uint32_t languages_server_to_client_length;
    char *languages_server_to_client;
    byte first_kex_packet_follows;
    uint32_t reserved;
} KEXINIT;

size_t fill_kexinit(KEXINIT *kexinit);

void parse_kexinit(const byte *buffer, KEXINIT *kexinit);

#endif //SSH_IMPLEMENTATION_KEXINIT_H
