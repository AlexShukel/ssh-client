//
// Created by Aleksandras on 2024-04-23.
//

#include "dekexinit.h"

void fill_dekexinit(DEKEXINIT *dekexinit) {
    dekexinit->msg_code = 30;
    dekexinit->ephemeral_key_length = KEY_LEN;

    // Generate a random key (4 bytes)
    FILE *urand = fopen("/dev/urandom", "r");
    fread(dekexinit->ephemeral_key, 1, KEY_LEN, urand);
    fclose(urand);
}
