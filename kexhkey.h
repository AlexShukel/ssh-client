//
// Created by aleksandras on 4/26/2024.
//

#ifndef SSH_IMPLEMENTATION_KEXHKEY_H
#define SSH_IMPLEMENTATION_KEXHKEY_H

#include <stdint.h>
#include "shared.h"

typedef struct {
    uint32_t host_key_length;
    uint32_t host_key_type_length;
    char *host_key_type;
    uint32_t rsa_public_exponent_length;
    byte *rsa_public_exponent;
    uint32_t rsa_modulus_length;
    byte *rsa_modulus;
} KEXHKEY;

size_t deserialize_KEXHKEY(const byte *buffer, KEXHKEY *kexhkey);

#endif //SSH_IMPLEMENTATION_KEXHKEY_H
