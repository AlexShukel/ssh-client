//
// Created by aleksandras on 4/26/2024.
//

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "kexhkey.h"
#include "utils.h"

size_t deserialize_KEXHKEY(const byte *buffer, KEXHKEY *kexhkey) {
    kexhkey->host_key_length = ntohl(*((uint32_t *) buffer));
    buffer += sizeof(uint32_t);

    DESERIALIZE_STRING(host_key_type, kexhkey, buffer);
    DESERIALIZE_STRING(rsa_public_exponent, kexhkey, buffer);
    DESERIALIZE_STRING(rsa_modulus, kexhkey, buffer);

    return 4 * sizeof(uint32_t) + kexhkey->host_key_type_length + kexhkey->rsa_public_exponent_length +
           kexhkey->rsa_modulus_length;
}
