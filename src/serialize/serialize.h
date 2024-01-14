#ifndef CMLS_SERIALIZE_H
#define CMLS_SERIALIZE_H

#include <jansson.h>
#include <stdbool.h>
#include <stddef.h>

size_t cmls_serialize_length_length(size_t len);
void   cmls_serialize_encode_header(size_t len, unsigned char* out);
bool   cmls_serialize_decode_header(unsigned char* data, size_t* len);

void cmls_serialize_test(json_t* entry);

#endif
