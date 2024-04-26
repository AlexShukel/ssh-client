//
// Created by aleksandras on 4/22/2024.
//

#ifndef SSH_IMPLEMENTATION_UTILS_H
#define SSH_IMPLEMENTATION_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "shared.h"

#define FILL_STRING(field_name, value, target) \
    target->field_name##_length = sizeof(value) - 1; \
    target->field_name = malloc(target->field_name##_length); \
    memcpy(target->field_name, value, target->field_name##_length) \

#define SERIALIZE_STRING(field_name, target, buffer) \
        size_t __##field_name##_length = htonl(target->field_name##_length); \
        memcpy(buffer, &__##field_name##_length, sizeof(uint32_t)); \
        buffer += sizeof(uint32_t); \
        memcpy(buffer, target->field_name, target->field_name##_length); \
        buffer += target->field_name##_length

#define DESERIALIZE_STRING(field_name, target, buffer) \
        target->field_name##_length = ntohl(*((uint32_t *) buffer)); \
        target->field_name = malloc(target->field_name##_length);    \
        buffer += sizeof(uint32_t);                                               \
        memcpy(target->field_name, buffer, target->field_name##_length);           \
        buffer += target->field_name##_length

bool starts_with(const char *str, const char *pattern, size_t pattern_size);

void send_data_in_packet(int s_socket, byte *data, size_t data_size);

#endif //SSH_IMPLEMENTATION_UTILS_H
