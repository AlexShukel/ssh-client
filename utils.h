//
// Created by aleksandras on 4/22/2024.
//

#ifndef SSH_IMPLEMENTATION_UTILS_H
#define SSH_IMPLEMENTATION_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool starts_with(const char *str, const char *pattern, size_t pattern_size);

void uint_to_little_endian(uint32_t* value);

#endif //SSH_IMPLEMENTATION_UTILS_H
