//
// Created by aleksandras on 4/22/2024.
//

#include <netinet/in.h>
#include "kexinit.h"
#include "utils.h"

#define FILL_ALGORITHM_STRING(name, value, kexinit) \
    kexinit->name##_length = sizeof(value) - 1; \
    kexinit->name = malloc(kexinit->name##_length); \
    memcpy(kexinit->name, value, kexinit->name##_length) \


size_t fill_kexinit(KEXINIT *kexinit) {
    kexinit->SSH_MSG_KEXINIT = 20; // SSH_MSG_KEXINIT value is 20

    // Generate a random cookie (16 bytes)
    FILE *urand = fopen("/dev/urandom", "r");
    fread(kexinit->cookie, 1, sizeof(kexinit->cookie), urand);
    fclose(urand);

    FILL_ALGORITHM_STRING(kex_algorithms, "curve25519-sha256", kexinit);
    FILL_ALGORITHM_STRING(server_host_key_algorithms, "rsa-sha2-512", kexinit);
    FILL_ALGORITHM_STRING(encryption_algorithms_client_to_server, "chacha20-poly1305@openssh.com", kexinit);
    FILL_ALGORITHM_STRING(encryption_algorithms_server_to_client, "chacha20-poly1305@openssh.com", kexinit);
    FILL_ALGORITHM_STRING(mac_algorithms_client_to_server, "umac-64-etm@openssh.com", kexinit);
    FILL_ALGORITHM_STRING(mac_algorithms_server_to_client, "umac-64-etm@openssh.com", kexinit);
    FILL_ALGORITHM_STRING(compression_algorithms_client_to_server, "none", kexinit);
    FILL_ALGORITHM_STRING(compression_algorithms_server_to_client, "none", kexinit);
    kexinit->languages_client_to_server_length = 0;
    kexinit->languages_client_to_server = NULL;
    kexinit->languages_server_to_client_length = 0;
    kexinit->languages_server_to_client = NULL;

    kexinit->first_kex_packet_follows = 0;
    kexinit->reserved = 0;

    return sizeof(byte) + 16 + 10 * sizeof(uint32_t) + sizeof(byte) + sizeof(uint32_t)
           + kexinit->kex_algorithms_length
           + kexinit->server_host_key_algorithms_length
           + kexinit->encryption_algorithms_client_to_server_length
           + kexinit->encryption_algorithms_server_to_client_length
           + kexinit->mac_algorithms_client_to_server_length
           + kexinit->mac_algorithms_server_to_client_length
           + kexinit->compression_algorithms_client_to_server_length
           + kexinit->compression_algorithms_server_to_client_length;
}

#define SERIALIZE_ALGORITHMS_STRING(name, kexinit, buffer) \
        netlong = htonl(kexinit->name##_length); \
        memcpy(buffer, &netlong, sizeof(uint32_t)); \
        buffer += sizeof(uint32_t); \
        memcpy(buffer, kexinit->name, kexinit->name##_length); \
        buffer += kexinit->name##_length

void serialize_KEXINIT(const KEXINIT *kexinit, byte *buffer) {
    memcpy(buffer, &kexinit->SSH_MSG_KEXINIT, sizeof(byte));
    buffer += sizeof(byte);
    memcpy(buffer, kexinit->cookie, 16);
    buffer += 16;

    uint32_t netlong;
    SERIALIZE_ALGORITHMS_STRING(kex_algorithms, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(server_host_key_algorithms, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(encryption_algorithms_client_to_server, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(encryption_algorithms_server_to_client, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(mac_algorithms_client_to_server, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(mac_algorithms_server_to_client, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(compression_algorithms_client_to_server, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(compression_algorithms_server_to_client, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(languages_client_to_server, kexinit, buffer);
    SERIALIZE_ALGORITHMS_STRING(languages_server_to_client, kexinit, buffer);

    memcpy(buffer, &kexinit->first_kex_packet_follows, sizeof(byte));
    buffer += sizeof(byte);

    netlong = htonl(kexinit->reserved);
    memcpy(buffer, &netlong, sizeof(uint32_t));
}

#define DESERIALIZE_ALGORITHMS_STRING(name, buffer, kexinit) \
        string_size = ntohl(*((uint32_t *) buffer)); \
        kexinit->name##_length = string_size; \
        kexinit->name = malloc(string_size); \
        buffer += sizeof(uint32_t); \
        memcpy(kexinit->name, buffer, string_size); \
        buffer += string_size

void deserialize_KEXINIT(const byte *buffer, KEXINIT *kexinit) {
    memcpy(&kexinit->SSH_MSG_KEXINIT, buffer, sizeof(byte));
    memcpy(kexinit->cookie, buffer + sizeof(byte), 16);

    buffer += 17;
    uint32_t string_size;

    DESERIALIZE_ALGORITHMS_STRING(kex_algorithms, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(server_host_key_algorithms, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(encryption_algorithms_client_to_server, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(encryption_algorithms_server_to_client, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(mac_algorithms_client_to_server, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(mac_algorithms_server_to_client, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(compression_algorithms_client_to_server, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(compression_algorithms_server_to_client, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(languages_client_to_server, buffer, kexinit);
    DESERIALIZE_ALGORITHMS_STRING(languages_server_to_client, buffer, kexinit);

    kexinit->first_kex_packet_follows = *buffer;
    buffer += 1;

    kexinit->reserved = ntohl(*((uint32_t *) buffer));
}
