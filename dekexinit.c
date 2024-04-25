//
// Created by Aleksandras on 2024-04-23.
//

#include "dekexinit.h"
#include <string.h>
#include <netinet/in.h>

void fill_dekexinit(DEKEXINIT *dekexinit) {
    dekexinit->msg_code = 30;
    dekexinit->ephemeral_key_length = KEY_LEN;

    // Generate a random key (4 bytes)
    FILE *urand = fopen("/dev/urandom", "r");
    fread(dekexinit->ephemeral_key, 1, KEY_LEN, urand);
    fclose(urand);
}

void serialize_dekexinit(const DEKEXINIT *dekexinit, byte *buffer) {
    memcpy(buffer, &dekexinit->msg_code, sizeof(byte));
    buffer += sizeof(byte);

    uint32_t netlong = htonl(dekexinit->ephemeral_key_length);
    memcpy(buffer, &netlong, sizeof(uint32_t));
    buffer += sizeof(uint32_t);

    memcpy(buffer, dekexinit->ephemeral_key, KEY_LEN);
}
