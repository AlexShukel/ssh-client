//
// Created by aleksandras on 4/22/2024.
//

#ifndef SSH_IMPLEMENTATION_UTILS_H
#define SSH_IMPLEMENTATION_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "shared.h"

bool starts_with(const char *str, const char *pattern, size_t pattern_size);

void send_data_in_packet(int s_socket, byte *data, size_t data_size);

#endif //SSH_IMPLEMENTATION_UTILS_H
