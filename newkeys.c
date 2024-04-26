//
// Created by aleksandras on 4/26/2024.
//

#include "newkeys.h"

void deserialize_NEWKEYS(const byte *buffer, NEWKEYS *newkeys) {
    newkeys->msg_code = *buffer;
}
