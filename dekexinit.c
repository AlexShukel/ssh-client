//
// Created by Aleksandras on 2024-04-23.
//

#include "dekexinit.h"
#include "utils.h"
#include <string.h>
#include <netinet/in.h>

size_t fill_dekexinit(DEKEXINIT *dekexinit) {
    dekexinit->msg_code = 30;
    dekexinit->ephemeral_key_length = KEY_LEN;

    // Generate a random key (4 bytes)
    FILE *urand = fopen("/dev/urandom", "r");
    fread(dekexinit->ephemeral_key, 1, KEY_LEN, urand);
    fclose(urand);

    return sizeof(byte) + sizeof(uint32_t) + KEY_LEN;
}

void serialize_dekexinit(const DEKEXINIT *dekexinit, byte *buffer) {
    memcpy(buffer, &dekexinit->msg_code, sizeof(byte));
    buffer += sizeof(byte);

    SERIALIZE_STRING(ephemeral_key, dekexinit, buffer);
}
