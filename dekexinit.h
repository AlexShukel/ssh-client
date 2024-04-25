//
// Created by Aleksandras on 2024-04-23.
//

#ifndef SSH_IMPLEMENTATION_DEKEX_H
#define SSH_IMPLEMENTATION_DEKEX_H

#include "shared.h"
#include <stdlib.h>
#include <stdio.h>

#define KEY_LEN 32

// Elliptic curve Diffie-Hellman Key Exchange
typedef struct {
    byte msg_code; // 30
    uint32_t ephemeral_key_length;
    byte ephemeral_key[KEY_LEN];
} DEKEXINIT;

void fill_dekexinit(DEKEXINIT *dekexinit);

void serialize_dekexinit(const DEKEXINIT *dekexinit, byte *buffer);

#endif //SSH_IMPLEMENTATION_DEKEX_H
