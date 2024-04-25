//
// Created by aleksandras on 4/22/2024.
//

#ifndef SSH_IMPLEMENTATION_PACKET_H
#define SSH_IMPLEMENTATION_PACKET_H

#include "shared.h"

#define MAX_PACKET_SIZE 32768

typedef struct {
    uint32_t packet_length; // not including mac and packet_length itself
    byte padding_length; // length of random_padding
    byte *payload; // contents of the packet
    /**
     * Arbitrary-length padding, such that the total length of
         (packet_length || padding_length || payload || random padding)
         is a multiple of the cipher block size or 8, whichever is larger.
     */
    byte *random_padding;
    byte *mac; // This may be a fixed-size
} Packet;

size_t fill_packet(Packet *packet, byte *payload, uint32_t payload_length, byte *mac);

void destroy_packet(Packet *packet);

void serialize_packet(const Packet *packet, byte *buffer);

void deserialize_packet(const byte *buffer, Packet *packet);

#endif //SSH_IMPLEMENTATION_PACKET_H
