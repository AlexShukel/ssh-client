//
// Created by Aleksandras on 2024-04-23.
//

#ifndef SSH_IMPLEMENTATION_DEKEXREPLY_H
#define SSH_IMPLEMENTATION_DEKEXREPLY_H

#include "shared.h"
#include "utils.h"
#include "kexhkey.h"

typedef struct {
    byte msg_code; // 31
    KEXHKEY kex_host_key;
    uint32_t ephemeral_public_key_length;
    byte *ephemeral_public_key;
    uint32_t signature_length;
    byte *signature;
} DEKEXREPLY;

void deserialize_DEKEXREPLY(const byte *buffer, DEKEXREPLY *dekexreply);

#endif //SSH_IMPLEMENTATION_DEKEXREPLY_H
