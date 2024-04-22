//
// Created by aleksandras on 4/22/2024.
//

#include "utils.h"

bool starts_with(const char *str, const char *pattern, size_t pattern_size) {
    for (size_t i = 0; i < pattern_size; ++i) {
        if (str[i] != pattern[i]) {
            return false;
        }
    }

    return true;
}

void uint_to_little_endian(uint32_t* value) {
    *value = ((*value >> 24) & 0xff) |
             ((*value << 8) & 0xff0000) |
             ((*value >> 8) & 0xff00) |
             ((*value << 24) & 0xff000000);
}
