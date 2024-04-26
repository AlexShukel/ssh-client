//
// Created by aleksandras on 4/26/2024.
//

#ifndef SSH_IMPLEMENTATION_NEWKEYS_H
#define SSH_IMPLEMENTATION_NEWKEYS_H

#include "shared.h"

typedef struct {
    byte msg_code; // 21
} NEWKEYS;

void deserialize_NEWKEYS(const byte *buffer, NEWKEYS *newkeys);

#endif //SSH_IMPLEMENTATION_NEWKEYS_H
