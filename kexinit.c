//
// Created by aleksandras on 4/22/2024.
//

#include "kexinit.h"
#include "utils.h"

size_t fill_kexinit(KEXINIT *kexinit) {
    // Fill in SSH_MSG_KEXINIT
    kexinit->SSH_MSG_KEXINIT = 20; // SSH_MSG_KEXINIT value is 20

    // Generate a random cookie (16 bytes)
    FILE *urand = fopen("/dev/urandom", "r");
    fread(kexinit->cookie, 1, sizeof(kexinit->cookie), urand);
    fclose(urand);

    char kex_algorithms[] = "curve25519-sha256";
    char server_host_key_algorithms[] = "rsa-sha2-512";
    char encryption_algorithms_client_to_server[] = "chacha20-poly1305@openssh.com";
    char encryption_algorithms_server_to_client[] = "aes128-ctr,aes256-ctr";
    char mac_algorithms_client_to_server[] = "hmac-sha1,hmac-sha256";
    char mac_algorithms_server_to_client[] = "hmac-sha1,hmac-sha256";
    char compression_algorithms_client_to_server[] = "none";
    char compression_algorithms_server_to_client[] = "none";

    // Fill in other fields with supported algorithms and settings
    // For demonstration purposes, we'll use example values
    kexinit->kex_algorithms = malloc(sizeof(kex_algorithms));
    kexinit->server_host_key_algorithms = malloc(sizeof(server_host_key_algorithms));
    kexinit->encryption_algorithms_client_to_server = malloc(sizeof(encryption_algorithms_client_to_server));
    kexinit->encryption_algorithms_server_to_client = malloc(sizeof(encryption_algorithms_server_to_client));
    kexinit->mac_algorithms_client_to_server = malloc(sizeof(mac_algorithms_client_to_server));
    kexinit->mac_algorithms_server_to_client = malloc(sizeof(mac_algorithms_server_to_client));
    kexinit->compression_algorithms_client_to_server = malloc(sizeof(compression_algorithms_client_to_server));
    kexinit->compression_algorithms_server_to_client = malloc(sizeof(compression_algorithms_server_to_client));
    kexinit->languages_client_to_server = NULL;
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

    kexinit->first_kex_packet_follows = 0; // Assuming first kex packet does not follow
    kexinit->reserved = 0; // Reserved for future extension

    return 7 + sizeof(kex_algorithms)
           + sizeof(server_host_key_algorithms)
           + sizeof(encryption_algorithms_client_to_server)
           + sizeof(encryption_algorithms_server_to_client)
           + sizeof(mac_algorithms_client_to_server)
           + sizeof(mac_algorithms_server_to_client)
           + sizeof(compression_algorithms_client_to_server)
           + sizeof(compression_algorithms_server_to_client);
}

void parse_kexinit(const byte *buffer, KEXINIT *kexinit) {
    memcpy(kexinit, buffer, sizeof(KEXINIT));

    buffer += 17;

    uint32_t string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->kex_algorithms_length = string_size;
    kexinit->kex_algorithms = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->kex_algorithms, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->server_host_key_algorithms_length = string_size;
    kexinit->server_host_key_algorithms = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->server_host_key_algorithms, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->encryption_algorithms_client_to_server_length = string_size;
    kexinit->encryption_algorithms_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->encryption_algorithms_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->encryption_algorithms_server_to_client_length = string_size;
    kexinit->encryption_algorithms_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->encryption_algorithms_server_to_client, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->mac_algorithms_client_to_server_length = string_size;
    kexinit->mac_algorithms_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->mac_algorithms_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->mac_algorithms_server_to_client_length = string_size;
    kexinit->mac_algorithms_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->mac_algorithms_server_to_client, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->compression_algorithms_client_to_server_length = string_size;
    kexinit->compression_algorithms_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->compression_algorithms_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->compression_algorithms_server_to_client_length = string_size;
    kexinit->compression_algorithms_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->compression_algorithms_server_to_client, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->languages_client_to_server_length = string_size;
    kexinit->languages_client_to_server = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->languages_client_to_server, buffer, string_size);
    buffer += string_size;

    string_size = *((uint32_t *) buffer);
    uint_to_little_endian(&string_size);
    kexinit->languages_server_to_client_length = string_size;
    kexinit->languages_server_to_client = malloc(string_size);
    buffer += sizeof(uint32_t);
    memcpy(kexinit->languages_server_to_client, buffer, string_size);
    buffer += string_size;

    kexinit->first_kex_packet_follows = *buffer;
    buffer += 1;

    kexinit->reserved = *((uint32_t *) buffer);
    uint_to_little_endian(&kexinit->reserved);
}
