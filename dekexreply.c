//
// Created by Aleksandras on 2024-04-23.
//

#include "dekexreply.h"

void deserialize_DEKEXREPLY(const byte *buffer, DEKEXREPLY *dekexreply) {
    dekexreply->msg_code = *buffer;
    buffer += sizeof(byte);

    KEXHKEY kexhkey;
    buffer += deserialize_KEXHKEY(buffer, &kexhkey);
    dekexreply->kex_host_key = kexhkey;

    DESERIALIZE_STRING(ephemeral_public_key, dekexreply, buffer);
    DESERIALIZE_STRING(signature, dekexreply, buffer);
}
