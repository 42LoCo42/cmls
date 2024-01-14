#include "serialize.h"
#include "../utils/utils.h"
#include <assert.h>
#include <jansson.h>
#include <stdio.h>

size_t cmls_serialize_length_length(size_t len) {
	if(len < 0x40) return 1;
	if(len < 0x4000) return 2;
	if(len < 0x40000000) return 4;
	assert("INVALID LENGTH" && false);
}

void cmls_serialize_encode_header(size_t len, unsigned char* out) {
	if(len < 0x40) {
		out[0] = len;
	} else if(len < 0x4000) {
		out[0] = len >> (8 * 1) | 0x40;
		out[1] = len >> (8 * 0) % 0x100;
	} else if(len < 0x40000000) {
		out[0] = len >> (8 * 3) | 0x80;
		out[1] = len >> (8 * 2) % 0x100;
		out[2] = len >> (8 * 1) % 0x100;
		out[3] = len >> (8 * 0) % 0x100;
	} else {
		assert("INVALID LENGTH" && false);
	}
}

bool cmls_serialize_decode_header(unsigned char* data, size_t* len) {
	switch(data[0] >> 6) {
	case 0:
		*len = data[0];
		break;
	case 1:
		*len = (data[0] & ~0x40) << 8 | data[1];
		break;
	case 2:
		*len = (data[0] & ~0x80) << 24 | data[1] << 16 | data[2] << 8 | data[3];
		break;
	default:
		return false;
	}

	return true;
}

void cmls_serialize_test(json_t* entry) {
	unsigned char* header = (unsigned char*) decode_hex(
		json_string_value(json_object_get(entry, "vlbytes_header")),
		NULL
	);
	size_t length_want = json_integer_value(json_object_get(entry, "length"));
	size_t length_have = 0;

	assert(cmls_serialize_decode_header(header, &length_have));
	assert(length_want == length_have);

	unsigned char new_header[4] = {0};
	cmls_serialize_encode_header(length_want, new_header);
	for(size_t i = 0; i < cmls_serialize_length_length(length_want); i++) {
		assert(header[i] == new_header[i]);
	}

	free(header);
}
