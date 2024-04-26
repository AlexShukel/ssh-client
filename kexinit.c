//
// Created by aleksandras on 4/22/2024.
//

#include <netinet/in.h>
#include "kexinit.h"
#include "utils.h"

size_t fill_kexinit(KEXINIT *kexinit) {
    kexinit->SSH_MSG_KEXINIT = 20; // SSH_MSG_KEXINIT value is 20

    // Generate a random cookie (16 bytes)
    FILE *urand = fopen("/dev/urandom", "r");
    fread(kexinit->cookie, 1, sizeof(kexinit->cookie), urand);
    fclose(urand);

    FILL_STRING(kex_algorithms, "curve25519-sha256", kexinit);
    FILL_STRING(server_host_key_algorithms, "rsa-sha2-512", kexinit);
    FILL_STRING(encryption_algorithms_client_to_server, "chacha20-poly1305@openssh.com", kexinit);
    FILL_STRING(encryption_algorithms_server_to_client, "chacha20-poly1305@openssh.com", kexinit);
    FILL_STRING(mac_algorithms_client_to_server, "umac-64-etm@openssh.com", kexinit);
    FILL_STRING(mac_algorithms_server_to_client, "umac-64-etm@openssh.com", kexinit);
    FILL_STRING(compression_algorithms_client_to_server, "none", kexinit);
    FILL_STRING(compression_algorithms_server_to_client, "none", kexinit);
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

void destroy_kexinit(KEXINIT *kexinit) {
    free(kexinit->kex_algorithms);
    free(kexinit->server_host_key_algorithms);
    free(kexinit->encryption_algorithms_client_to_server);
    free(kexinit->encryption_algorithms_server_to_client);
    free(kexinit->mac_algorithms_client_to_server);
    free(kexinit->mac_algorithms_server_to_client);
    free(kexinit->compression_algorithms_client_to_server);
    free(kexinit->compression_algorithms_server_to_client);
}

void serialize_KEXINIT(const KEXINIT *kexinit, byte *buffer) {
    memcpy(buffer, &kexinit->SSH_MSG_KEXINIT, sizeof(byte));
    buffer += sizeof(byte);
    memcpy(buffer, kexinit->cookie, 16);
    buffer += 16;

    SERIALIZE_STRING(kex_algorithms, kexinit, buffer);
    SERIALIZE_STRING(server_host_key_algorithms, kexinit, buffer);
    SERIALIZE_STRING(encryption_algorithms_client_to_server, kexinit, buffer);
    SERIALIZE_STRING(encryption_algorithms_server_to_client, kexinit, buffer);
    SERIALIZE_STRING(mac_algorithms_client_to_server, kexinit, buffer);
    SERIALIZE_STRING(mac_algorithms_server_to_client, kexinit, buffer);
    SERIALIZE_STRING(compression_algorithms_client_to_server, kexinit, buffer);
    SERIALIZE_STRING(compression_algorithms_server_to_client, kexinit, buffer);
    SERIALIZE_STRING(languages_client_to_server, kexinit, buffer);
    SERIALIZE_STRING(languages_server_to_client, kexinit, buffer);

    memcpy(buffer, &kexinit->first_kex_packet_follows, sizeof(byte));
    buffer += sizeof(byte);

    uint32_t netlong = htonl(kexinit->reserved);
    memcpy(buffer, &netlong, sizeof(uint32_t));
}

void deserialize_KEXINIT(const byte *buffer, KEXINIT *kexinit) {
    memcpy(&kexinit->SSH_MSG_KEXINIT, buffer, sizeof(byte));
    memcpy(kexinit->cookie, buffer + sizeof(byte), 16);

    buffer += 17;
    uint32_t string_size;

    DESERIALIZE_STRING(kex_algorithms, kexinit, buffer);
    DESERIALIZE_STRING(server_host_key_algorithms, kexinit, buffer);
    DESERIALIZE_STRING(encryption_algorithms_client_to_server, kexinit, buffer);
    DESERIALIZE_STRING(encryption_algorithms_server_to_client, kexinit, buffer);
    DESERIALIZE_STRING(mac_algorithms_client_to_server, kexinit, buffer);
    DESERIALIZE_STRING(mac_algorithms_server_to_client, kexinit, buffer);
    DESERIALIZE_STRING(compression_algorithms_client_to_server, kexinit, buffer);
    DESERIALIZE_STRING(compression_algorithms_server_to_client, kexinit, buffer);
    DESERIALIZE_STRING(languages_client_to_server, kexinit, buffer);
    DESERIALIZE_STRING(languages_server_to_client, kexinit, buffer);

    kexinit->first_kex_packet_follows = *buffer;
    buffer += 1;

    kexinit->reserved = ntohl(*((uint32_t *) buffer));
}
