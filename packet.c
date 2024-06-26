//
// Created by aleksandras on 4/22/2024.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "packet.h"
#include <netinet/in.h>
#include "packet.h"
#include "utils.h"

    // Calculate padding length to make the total length a multiple of 8
size_t fill_packet(Packet *packet, byte *payload, uint32_t payload_length, byte *mac) {
    byte block_size = 8; // Block size, assuming 8 for example
//    uint32_t padding_length = (block_size - (total_length % block_size)) % block_size;
    size_t total_length = sizeof(uint32_t) + sizeof(byte) + payload_length;
    uint32_t padding_length = block_size - (total_length % block_size);

    // Fill packet fields
    packet->packet_length = payload_length + padding_length + sizeof(byte);
    packet->padding_length = padding_length;
    packet->payload = payload;
    packet->mac = mac;

    // Generate random padding
    packet->random_padding = (byte *) malloc(padding_length * sizeof(byte));
    for (int i = 0; i < padding_length; i++) {
//        packet->random_padding[i] = rand() % 256; // Fill with random bytes (0-255)
        // TODO: generate random bytes here
        packet->random_padding[i] = 0;
    }

    return total_length + padding_length;
}

void destroy_packet(Packet *packet) {
    free(packet->payload);
    free(packet->random_padding);
}

void serialize_packet(const Packet *packet, byte *buffer) {
    uint32_t netlong = htonl(packet->packet_length);
    memcpy(buffer, &netlong, sizeof(uint32_t));
    buffer += sizeof(uint32_t);

    memcpy(buffer, &packet->padding_length, sizeof(byte));
    buffer += sizeof(byte);

    size_t payload_size = packet->packet_length - packet->padding_length - 1;
    memcpy(buffer, packet->payload, payload_size);
    buffer += payload_size;

    memcpy(buffer, packet->random_padding, packet->padding_length);

    // TODO: serialize mac
}

size_t deserialize_packet(const byte *buffer, Packet *packet) {
    packet->packet_length = htonl(*((uint32_t *) buffer));
    memcpy(&packet->padding_length, buffer + sizeof(uint32_t), sizeof(byte));

    size_t payload_size = packet->packet_length - packet->padding_length - 1;
    packet->payload = malloc(payload_size);
    memcpy(packet->payload, buffer + sizeof(uint32_t) + sizeof(byte), payload_size);

    packet->random_padding = malloc(packet->padding_length);
    memcpy(packet->random_padding, buffer + sizeof(uint32_t) + sizeof(byte) + payload_size, packet->padding_length);

    // TODO: deserialize mac
    return packet->packet_length + sizeof(uint32_t);
}
