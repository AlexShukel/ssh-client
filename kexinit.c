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

    char kex_algorithms[] = "curve25519-sha256";
    char server_host_key_algorithms[] = "rsa-sha2-512";
    char encryption_algorithms_client_to_server[] = "chacha20-poly1305@openssh.com";
    char encryption_algorithms_server_to_client[] = "chacha20-poly1305@openssh.com";
    char mac_algorithms_client_to_server[] = "umac-64-etm@openssh.com";
    char mac_algorithms_server_to_client[] = "umac-64-etm@openssh.com";
    char compression_algorithms_client_to_server[] = "none";
    char compression_algorithms_server_to_client[] = "none";

    kexinit->kex_algorithms_length = sizeof(kex_algorithms);
    kexinit->kex_algorithms = malloc(sizeof(kex_algorithms));
    kexinit->server_host_key_algorithms_length = sizeof(server_host_key_algorithms);
    kexinit->server_host_key_algorithms = malloc(sizeof(server_host_key_algorithms));
    kexinit->encryption_algorithms_client_to_server_length = sizeof(encryption_algorithms_client_to_server);
    kexinit->encryption_algorithms_client_to_server = malloc(sizeof(encryption_algorithms_client_to_server));
    kexinit->encryption_algorithms_server_to_client_length = sizeof(encryption_algorithms_server_to_client);
    kexinit->encryption_algorithms_server_to_client = malloc(sizeof(encryption_algorithms_server_to_client));
    kexinit->mac_algorithms_client_to_server_length = sizeof(mac_algorithms_client_to_server);
    kexinit->mac_algorithms_client_to_server = malloc(sizeof(mac_algorithms_client_to_server));
    kexinit->mac_algorithms_server_to_client_length = sizeof(mac_algorithms_server_to_client);
    kexinit->mac_algorithms_server_to_client = malloc(sizeof(mac_algorithms_server_to_client));
    kexinit->compression_algorithms_client_to_server_length = sizeof(compression_algorithms_client_to_server);
    kexinit->compression_algorithms_client_to_server = malloc(sizeof(compression_algorithms_client_to_server));
    kexinit->compression_algorithms_server_to_client_length = sizeof(compression_algorithms_server_to_client);
    kexinit->compression_algorithms_server_to_client = malloc(sizeof(compression_algorithms_server_to_client));
    kexinit->languages_client_to_server_length = 0;
    kexinit->languages_client_to_server = NULL;
    kexinit->languages_server_to_client_length = 0;
    kexinit->languages_server_to_client = NULL;

    memcpy(kexinit->kex_algorithms, kex_algorithms, sizeof(kex_algorithms));
    memcpy(kexinit->server_host_key_algorithms, server_host_key_algorithms, sizeof(server_host_key_algorithms));
    memcpy(kexinit->encryption_algorithms_client_to_server, encryption_algorithms_client_to_server,
           sizeof(encryption_algorithms_client_to_server));
    memcpy(kexinit->encryption_algorithms_server_to_client, encryption_algorithms_server_to_client,
           sizeof(encryption_algorithms_server_to_client));
    memcpy(kexinit->mac_algorithms_client_to_server, mac_algorithms_client_to_server,
           sizeof(mac_algorithms_client_to_server));
    memcpy(kexinit->mac_algorithms_server_to_client, mac_algorithms_server_to_client,
           sizeof(mac_algorithms_server_to_client));
    memcpy(kexinit->compression_algorithms_client_to_server, compression_algorithms_client_to_server,
           sizeof(compression_algorithms_client_to_server));
    memcpy(kexinit->compression_algorithms_server_to_client, compression_algorithms_server_to_client,
           sizeof(compression_algorithms_server_to_client));

    kexinit->first_kex_packet_follows = 0;
    kexinit->reserved = 0;

    return sizeof(byte) + 16 + 10 * sizeof(uint32_t) + sizeof(byte) + sizeof(uint32_t)
           + sizeof(kex_algorithms)
           + sizeof(server_host_key_algorithms)
           + sizeof(encryption_algorithms_client_to_server)
           + sizeof(encryption_algorithms_server_to_client)
           + sizeof(mac_algorithms_client_to_server)
           + sizeof(mac_algorithms_server_to_client)
           + sizeof(compression_algorithms_client_to_server)
           + sizeof(compression_algorithms_server_to_client);
}

void serialize_KEXINIT(const KEXINIT *kexinit, byte *buffer) {
    memcpy(buffer, &kexinit->SSH_MSG_KEXINIT, sizeof(byte));

}

void deserialize_KEXINIT(const byte *buffer, KEXINIT *kexinit) {
    memcpy(&kexinit->SSH_MSG_KEXINIT, buffer, sizeof(byte));
    memcpy(kexinit->cookie, buffer + sizeof(byte), 16);

    buffer += 17;

    uint32_t string_size = ntohl(*((uint32_t *) buffer));
    kexinit->kex_algorithms_length = string_size;
    kexinit->kex_algorithms = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->kex_algorithms, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->server_host_key_algorithms_length = string_size;
    kexinit->server_host_key_algorithms = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->server_host_key_algorithms, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->encryption_algorithms_client_to_server_length = string_size;
    kexinit->encryption_algorithms_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->encryption_algorithms_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->encryption_algorithms_server_to_client_length = string_size;
    kexinit->encryption_algorithms_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->encryption_algorithms_server_to_client, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->mac_algorithms_client_to_server_length = string_size;
    kexinit->mac_algorithms_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->mac_algorithms_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->mac_algorithms_server_to_client_length = string_size;
    kexinit->mac_algorithms_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->mac_algorithms_server_to_client, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->compression_algorithms_client_to_server_length = string_size;
    kexinit->compression_algorithms_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->compression_algorithms_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->compression_algorithms_server_to_client_length = string_size;
    kexinit->compression_algorithms_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->compression_algorithms_server_to_client, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->languages_client_to_server_length = string_size;
    kexinit->languages_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->languages_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = ntohl(*((uint32_t *) buffer));
    kexinit->languages_server_to_client_length = string_size;
    kexinit->languages_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->languages_server_to_client, buffer, string_size);
    buffer += string_size;

    kexinit->first_kex_packet_follows = *buffer;
    buffer += 1;

    kexinit->reserved = ntohl(*((uint32_t *) buffer));
}
