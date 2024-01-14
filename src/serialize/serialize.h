#ifndef CMLS_SERIALIZE_H
#define CMLS_SERIALIZE_H

#include "../utils/utils.h"
#include <jansson.h>
#include <stdbool.h>
#include <stddef.h>

size_t cmls_serialize_length_length(size_t len);
void   cmls_serialize_encode_header(size_t len, unsigned char* out);
bool   cmls_serialize_decode_header(const unsigned char* data, size_t* len);

void cmls_serialize_encode(const unsigned char* data, size_t len, bytes* vec);

void cmls_serialize_test(const json_t* entry);

#endif
