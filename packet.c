//
// Created by aleksandras on 4/22/2024.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "packet.h"
#include "utils.h"

size_t fill_packet(Packet *packet, byte *payload, uint32_t payload_length, byte *mac) {
    // Calculate padding length to make the total length a multiple of 8
    byte block_size = 8; // Block size, assuming 8 for example
    size_t total_length = sizeof(uint32_t) + sizeof(byte) + payload_length + packet->padding_length + block_size;
    uint32_t padding_length = block_size - (total_length % block_size);

    // Fill packet fields
    packet->packet_length = payload_length + packet->padding_length + padding_length + sizeof(uint32_t) + sizeof(byte);
    packet->padding_length = padding_length;
    packet->payload = payload;
    packet->mac = mac;

    // Generate random padding
    packet->random_padding = (byte *) malloc(padding_length * sizeof(byte));
    for (int i = 0; i < padding_length; i++) {
        packet->random_padding[i] = rand() % 256; // Fill with random bytes (0-255)
    }

    return total_length;
}

void parse_packet(const byte *buffer, Packet *packet) {
    memcpy(packet, buffer, sizeof(Packet));
    uint_to_little_endian(&packet->packet_length);

    size_t payload_size = packet->packet_length - packet->padding_length - 1;
    packet->payload = malloc(payload_size);
    memcpy(packet->payload, buffer + 5, payload_size);
}