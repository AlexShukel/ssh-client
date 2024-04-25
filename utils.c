//
// Created by aleksandras on 4/22/2024.
//

#include "utils.h"
#include "packet.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

bool starts_with(const char *str, const char *pattern, size_t pattern_size) {
    for (size_t i = 0; i < pattern_size; ++i) {
        if (str[i] != pattern[i]) {
            return false;
        }
    }

    return true;
}

void send_data_in_packet(int s_socket, byte *data, size_t data_size) {
    Packet packet;
    size_t packet_size = fill_packet(&packet, data, data_size, NULL);
    byte *buffer = malloc(packet_size);
    serialize_packet(&packet, buffer);
    size_t size = send(s_socket, buffer, packet_size, 0);

    if (size == -1) {
        close(s_socket);
        fprintf(stderr, "ERROR: failed to receive a KEXINIT packet\n");
        exit(1);
    }

    destroy_packet(&packet);
}
